#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "smb2/smb2.h"
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "helpers/path.h"
#include "fst/fstspecific.h"
#include "fstops/GetFileInfo.h"
#include "helpers/errors.h"
#include "helpers/afpinfo.h"
#include "helpers/closerequest.h"
#include "fstops/open.h"

#define ACCESS_TYPE_COUNT 3

/*
 * Set createRequest.DesiredAccess and createRequest.ShareAccess to reflect
 * a GS/OS access word and corresponding sharing modes (using either GS/OS
 * or P16 sharing rules).
 */
void SetOpenAccess(Word access, bool p16Sharing) {
    // See GS/OS Ref p. 67 & 397 for GS/OS-style and P16-style sharing modes
    switch (access) {
    case readEnable:
        createRequest.DesiredAccess = FILE_READ_DATA | FILE_READ_ATTRIBUTES;
        if (p16Sharing) {
            createRequest.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
        } else {
            createRequest.ShareAccess = FILE_SHARE_READ;
        }
        break;

    case writeEnable:
        // TODO check if FILE_READ_ATTRIBUTES is needed for write-only mode
        createRequest.DesiredAccess = FILE_WRITE_DATA | FILE_APPEND_DATA |
            FILE_WRITE_ATTRIBUTES;
        if (p16Sharing) {
            createRequest.ShareAccess = FILE_SHARE_READ;
        } else {
            createRequest.ShareAccess = 0;
        }
        break;

    case readWriteEnable:    
        createRequest.DesiredAccess = FILE_READ_DATA | FILE_WRITE_DATA | 
            FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
        if (p16Sharing) {
            createRequest.ShareAccess = FILE_SHARE_READ;
        } else {
            createRequest.ShareAccess = 0;
        }
        break;
    }
}

Word Open(void *pblock, void *gsosdp, Word pcount) {
    static Word requestAccess[ACCESS_TYPE_COUNT];
    int i;
    Word result;
    DIB *dib;
    //SMB2_FILEID fileID;
    VirtualPointer vp;
    VCR *vcr;
    GSString *volName;
    bool oom;
    FCR *fcr;
    Word retval = 0;
    static SMB2_FILEID fileID;
    enum {openDataFork, openResourceFork, openOrCreateResourceFork} forkOp;

    dib = GetDIB(gsosdp, 1);
    if (dib == NULL)
        return volNotFound;

    // Determine allowable access modes (most to least preferred)
    if (pcount >= 3 && ((OpenRecGS*)pblock)->requestAccess != 0) {
        requestAccess[0] = ((OpenRecGS*)pblock)->requestAccess;
        requestAccess[1] = 0;
    } else {
        requestAccess[0] = readWriteEnable;
        requestAccess[1] = readEnable;
        requestAccess[2] = writeEnable;
    }
    
    if (pcount >= 4 && ((OpenRecGS*)pblock)->resourceNumber != 0) {
        if (((OpenRecGS*)pblock)->resourceNumber != 1)
            return paramRangeErr;
        forkOp = openResourceFork;
    } else {
        forkOp = openDataFork;
    }

retry:
    /*
     * Open file
     */
    createRequest.SecurityFlags = 0;
    createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    createRequest.ImpersonationLevel = Impersonation;
    createRequest.SmbCreateFlags = 0;
    createRequest.Reserved = 0;
    createRequest.FileAttributes = 0;
    createRequest.CreateOptions = 0; // TODO maybe FILE_NO_EA_KNOWLEDGE
    createRequest.NameOffset =
        sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
    createRequest.CreateContextsOffset = 0;
    createRequest.CreateContextsLength = 0;

    if (forkOp == openOrCreateResourceFork) {
        createRequest.CreateDisposition = FILE_OPEN_IF;
    } else {
        createRequest.CreateDisposition = FILE_OPEN;
    }

    // translate filename to SMB format
    createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1, createRequest.Buffer,
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
    if (createRequest.NameLength == 0xFFFF)
        return badPathSyntax;
    isRootDir = createRequest.NameLength == 0;

    if (forkOp >= openResourceFork) {
        if (createRequest.NameLength >
            sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer)
            - sizeof(resourceForkSuffix))
            return badPathSyntax;
        memcpy(createRequest.Buffer + createRequest.NameLength,
            resourceForkSuffix, sizeof(resourceForkSuffix));
        createRequest.NameLength += sizeof(resourceForkSuffix);
    }

    for (i = 0; i < ACCESS_TYPE_COUNT; i++) {
        switch (requestAccess[i]) {
        case readEnable:
        case writeEnable:
        case readWriteEnable:    
            SetOpenAccess(requestAccess[i], pcount == 0);
            break;
    
        case 0:
            goto open_done;
    
        default:
            return invalidAccess;
        }

        result = SendRequestAndGetResponse(dib, SMB2_CREATE,
            sizeof(createRequest) + createRequest.NameLength);
        if (result != rsFailed)
            break;
        if (msg.smb2Header.Status == STATUS_OBJECT_NAME_NOT_FOUND)
            break;
    }
open_done:
    if (result != rsDone) {
        if (result == rsFailed
        && msg.smb2Header.Status == STATUS_OBJECT_NAME_NOT_FOUND) {
            if (forkOp == openResourceFork) {
                /*
                 * macOS will give STATUS_OBJECT_NAME_NOT_FOUND when trying to
                 * open a 0-length resource fork, even if we previously created
                 * it successfully.  To work around this, we check if the file
                 * exists at all, and if it does then we open the resource fork
                 * with the "create if not present" setting.  This means that
                 * resource forks can be created just by opening them, but that
                 * shouldn't be a problem -- it's similar to HFS.
                 */
                createRequest.SecurityFlags = 0;
                createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
                createRequest.ImpersonationLevel = Impersonation;
                createRequest.SmbCreateFlags = 0;
                createRequest.Reserved = 0;
                createRequest.DesiredAccess = FILE_READ_ATTRIBUTES;
                createRequest.FileAttributes = 0;
                createRequest.ShareAccess =
                    FILE_SHARE_READ | FILE_SHARE_WRITE;
                createRequest.CreateDisposition = FILE_OPEN;
                createRequest.CreateOptions = 0;
                createRequest.NameOffset =
                    sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
                createRequest.CreateContextsOffset = 0;
                createRequest.CreateContextsLength = 0;

                createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1,
                    createRequest.Buffer,
                    sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
                if (createRequest.NameLength == 0xFFFF)
                    return badPathSyntax;

                result = SendRequestAndGetResponse(dib, SMB2_CREATE,
                    sizeof(createRequest) + createRequest.NameLength);
                if (result != rsDone)
                    return ConvertError(result);
                
                fileID = createResponse.FileId;
                
                result = SendCloseRequestAndGetResponse(dib, &fileID);
                // ignore any errors on close
                
                forkOp = openOrCreateResourceFork;
                goto retry;
            } else if (forkOp == openOrCreateResourceFork) {
                return resForkNotFound;
            }
        }
        return ConvertError(result);
    }
    
    fileID = createResponse.FileId;

    retval = GetVCR(dib, &vcr);
    if (retval != 0)
        goto close_on_error2;
    
    volName = dib->volName;
    if (volName->length > GBUF_SIZE - 3) {
        retval = badPathSyntax;
        goto close_on_error2;
    }
    *(Word*)gbuf = volName->length + 1;
    gbuf[2] = ':';
    memcpy(gbuf+3, volName->text, volName->length);

    asm {
        stz oom
        ldx gbuf
        ldy gbuf+2
        phd
        lda gsosdp
        tcd
        lda #sizeof(FCR)
        jsl ALLOC_FCR
        pld
        stx vp
        sty vp+2
        rol oom
    }
    if (oom) {
        retval = outOfMem;
        goto close_on_error2;
    }
    
    DerefVP(fcr,vp);
    
    vcr->openCount++;
    fcr->fstID = smbFSID;
    fcr->volID = vcr->id;
    fcr->access = requestAccess[i] | ACCESS_FLAG_CLEAN;
    if (forkOp >= openResourceFork)
         fcr->access |= ACCESS_FLAG_RFORK;
    
    fcr->fileID = fileID;
    fcr->dirEntryNum = 0;
    fcr->nextServerEntryNum = -1;
    fcr->smbFlags = pcount == 0 ? SMB_FLAG_P16SHARING : 0;
    fcr->createTime = createResponse.CreationTime;

    /*
     * Cache EOF to use in checking whether SetMark goes past EOF.
     * Our copy of the EOF should remain valid if the server fully enforces
     * the sharing rules, but we do not consider it fully authoritative and
     * therefore do not rely on it for anything else.
     *
     * Note: [MS-SMB2] up to v20240423 says that EndofFile is always the EOF
     * of the main stream, but Microsoft has confirmed to me that it is
     * actually the EOF of the stream being opened.  In testing, macOS and
     * Samba behave this way too.
     */
    fcr->eof = createResponse.EndofFile;

    if (pcount == 0) {
        #define pblock ((OpenRec*)pblock)
        
        pblock->openRefNum = fcr->refNum;
        
        #undef pblock
    } else {
        #define pblock ((OpenRecGS*)pblock)

        if (pcount >= 5) {
            basicInfo.CreationTime = createResponse.CreationTime;
            basicInfo.LastWriteTime = createResponse.LastWriteTime;
            basicInfo.FileAttributes = createResponse.FileAttributes;
            
            if (((OpenRecGS*)pblock)->resourceNumber == 0) {
                dataEOF = createResponse.EndofFile;
                dataAlloc = createResponse.AllocationSize;
                haveDataForkSizes = true;
            } else {
                haveDataForkSizes = false;
            }
            
            retval = GetFileInfo_Impl(
                (char*)&pblock->access - offsetof(FileInfoRecGS, access),
                gsosdp, pcount - 3, true, createResponse.FileId);
            if (retval)
                goto close_on_error1;
        }

        pblock->refNum = fcr->refNum;

        #undef pblock
    }
    
    return 0;

close_on_error1:
    /*
     * Release FCR if we got an error after it was allocated
     */
    i = fcr->refNum;
    asm {
        ldx i
        phd
        lda gsosdp
        tcd
        txa
        jsl RELEASE_FCR
        pld
    }

    vcr->openCount--;

close_on_error2:
    /*
     * Close file if we got an error
     */
    result = SendCloseRequestAndGetResponse(dib, &fileID);
    // Ignore error here, since we're already reporting some kind or error
    
    return retval;
}
