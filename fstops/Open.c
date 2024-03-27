#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "smb2.h"
#include "driver.h"
#include "gsosutils.h"
#include "path.h"
#include "fstspecific.h"

#define ACCESS_TYPE_COUNT 3

static char16_t resourceForkSuffix[19] = u":AFP_Resource:$DATA";

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

    /*
     * Open file
     */
    createRequest.SecurityFlags = 0;
    createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    createRequest.ImpersonationLevel = Impersonation;
    createRequest.SmbCreateFlags = 0;
    createRequest.Reserved = 0;
    createRequest.FileAttributes = 0;
    createRequest.CreateDisposition = FILE_OPEN;
    createRequest.CreateOptions = 0; // TODO maybe FILE_NO_EA_KNOWLEDGE
    createRequest.NameOffset =
        sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
    createRequest.CreateContextsOffset = 0;
    createRequest.CreateContextsLength = 0;

    // translate filename to SMB format
    createRequest.NameLength = GSPathToSMB(gsosdp, 1, createRequest.Buffer,
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
    if (createRequest.NameLength == 0xFFFF)
        return badPathSyntax;

    if (pcount >= 4 && ((OpenRecGS*)pblock)->resourceNumber != 0) {
        if (((OpenRecGS*)pblock)->resourceNumber != 1)
            return paramRangeErr;
        if (createRequest.NameLength >
            sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer)
            - sizeof(resourceForkSuffix))
            return badPathSyntax;
        memcpy(createRequest.Buffer + createRequest.NameLength,
            resourceForkSuffix, sizeof(resourceForkSuffix));
        createRequest.NameLength += sizeof(resourceForkSuffix);
    }

    // See GS/OS Ref p. 67 & 397 for GS/OS-style and P16-style sharing modes
    for (i = 0; i < ACCESS_TYPE_COUNT; i++) {
        switch (requestAccess[i]) {
        case readEnable:
            createRequest.DesiredAccess = FILE_READ_DATA | FILE_READ_ATTRIBUTES;
            if (pcount != 0) {
                createRequest.ShareAccess = FILE_SHARE_READ;
            } else {
                createRequest.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
            }
            break;
    
        case writeEnable:
            // TODO check if FILE_READ_ATTRIBUTES is needed for write-only mode
            createRequest.DesiredAccess = FILE_WRITE_DATA | FILE_APPEND_DATA |
                FILE_WRITE_ATTRIBUTES;
            if (pcount != 0) {
                createRequest.ShareAccess = 0;
            } else {
                createRequest.ShareAccess = FILE_SHARE_READ;
            }
            break;
    
        case readWriteEnable:    
            createRequest.DesiredAccess = FILE_READ_DATA | FILE_WRITE_DATA | 
                FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
            if (pcount != 0) {
                createRequest.ShareAccess = 0;
            } else {
                createRequest.ShareAccess = FILE_SHARE_READ;
            }
            break;
    
        case 0:
            goto open_done;
    
        default:
            return invalidAccess;
        }

        result = SendRequestAndGetResponse(dib->session, SMB2_CREATE,
            dib->treeId, sizeof(createRequest) + createRequest.NameLength);
        if (result != rsFailed)
            break;
        if (msg.smb2Header.Status == STATUS_OBJECT_NAME_NOT_FOUND)
            break;
    }
open_done:
    if (result != rsDone) {
        // TODO give appropriate error code
        return networkError;
    }

    vp = dib->vcrVP;
    DerefVP(vcr,vp);
    vp = vcr->name;
    DerefVP(volName,vp);
    
    if (volName->length > GBUF_SIZE - 3)
        return badPathSyntax;
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
        // TODO close file on server
        return outOfMem;
    }
    
    DerefVP(fcr,vp);
    
    vcr->openCount++;
    fcr->fstID = smbFSID;
    fcr->volID = vcr->id;
    fcr->access = requestAccess[i] | ACCESS_FLAG_CLEAN;
    if (pcount >= 4 && ((OpenRecGS*)pblock)->resourceNumber != 0)
         fcr->access |= ACCESS_FLAG_RFORK;
    
    fcr->fileID = createResponse.FileId;
    
    // TODO fill in info, depending on pcount
    
    if (pcount == 0) {
        #define pblock ((OpenRec*)pblock)
        
        pblock->openRefNum = fcr->refNum;
        
        #undef pblock
    } else {
        #define pblock ((OpenRecGS*)pblock)
        
        pblock->refNum = fcr->refNum;
        
        #undef pblock
    }
    
    return 0;
}
