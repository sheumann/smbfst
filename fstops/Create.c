#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "smb2.h"
#include "driver.h"
#include "gsosutils.h"
#include "fileinfo.h"
#include "path.h"
#include "endian.h"
#include "fstspecific.h"
#include "helpers/filetype.h"
#include "helpers/datetime.h"
#include "helpers/attributes.h"
#include "helpers/errors.h"

#define extendExistingFile 0x8005

/*
 * Add a create context to an otherwise-assembled SMB2 CREATE request.
 *
 * name gives the name of the context (must be 4 bytes).
 * data and dataLen specify the buffer with the context data.
 * *msgLen is the length of the CREATE request, which will be updated.
 *
 * Returns true on success, false on failure (not enough space).
 */
static bool AddCreateContext(uint32_t name, void *data, uint16_t dataLen,
    uint16_t *msgLen) {

    uint32_t pos;
    uint32_t newLen;
    SMB2_CREATE_CONTEXT *ctx;
    
    // calculate position of new context in message (8-byte aligned)
    pos = ((uint32_t)*msgLen + 7) & 0xFFFFFFF8;
    
    // calculate message length with context, and check if it's too big
    newLen = pos + sizeof(SMB2_CREATE_CONTEXT) + dataLen;
    if (newLen > sizeof(msg.body))
        return false;
    
    // zero out any padding added for alignment
    *(uint64_t*)(&msg.body[*msgLen]) = 0;
    
    ctx = (SMB2_CREATE_CONTEXT *)(&msg.body[pos]);

    ctx->Next = 0;
    ctx->NameOffset = offsetof(SMB2_CREATE_CONTEXT, Name);
    ctx->NameLength = sizeof(ctx->Name);
    ctx->Reserved = 0;
    ctx->DataOffset = offsetof(SMB2_CREATE_CONTEXT, Data);
    ctx->DataLength = dataLen;
    ctx->Name = hton32(name);
    ctx->Padding = 0;
    memcpy(ctx->Data, data, dataLen);

    if (createRequest.CreateContextsOffset == 0) {
        createRequest.CreateContextsOffset = sizeof(SMB2Header) + pos;
        createRequest.CreateContextsLength =
            sizeof(SMB2_CREATE_CONTEXT) + dataLen;
    } else {
        ctx = (SMB2_CREATE_CONTEXT *)
            ((char*)&msg.smb2Header + createRequest.CreateContextsOffset);
        while (ctx->Next != 0) {
            ctx = (SMB2_CREATE_CONTEXT *)((char*)ctx + ctx->Next);
        }
        ctx->Next = pos - ((char*)ctx - (char*)&msg.body);
        createRequest.CreateContextsLength += newLen - *msgLen;
    }

    *msgLen = newLen;

    return true;
}

/*
 * Notes on Create behavior under ProDOS FST:
 *
 * If storageType == $8005, most other params (except resourceEOF) are ignored.
 * eof/resourceEOF indicate space to preallocate, but do not set the EOF.
 * fileType = $0F with storageType not specified creates a directory.
 * fileType = $0F with non-directory storageType creates a file with type $0F.
 * storageType = $000D (directoryFile) forces file type to $0F.
 * storageType = $8005 on a nonexistent file works like storageType = $0005.
 *
 * We generally try to match this behavior.
 */

Word Create(void *pblock, void *gsosdp, Word pcount) {
    Word result;
    DIB *dib;
    static SMB2_FILEID fileID, infoFileID;
    Word retval = 0;
    uint16_t msgLen;

    uint32_t attributes, initialAttributes;
    uint64_t creationTime = 0;

    // Settings for create, initialized to default values
    Word access =
        readEnable | writeEnable | renameEnable | destroyEnable | backupNeeded;
    FileType fileType = {0, 0};
    Word storageType = standardFile;
    static uint64_t eof;
    static uint64_t resourceEOF;
    ProDOSTime createDateTime = {0, 0};
    
    eof = 0;
    resourceEOF = 0;

    dib = GetDIB(gsosdp, 1);
    if (dib == NULL)
        return volNotFound;

    /*
     * Get parameters
     */
    if (pcount == 0) {
        #define pblock ((FileRec*)pblock)
        
        access = pblock->fAccess;
        fileType.fileType = pblock->fileType;
        fileType.auxType = pblock->auxType;
        storageType = pblock->storageType;
        if (storageType <= 0x0003)
            storageType = pblock->storageType = standardFile;
        createDateTime.date = pblock->createDate;
        createDateTime.time = pblock->createTime;
        
        #undef pblock
    } else {
        #define pblock ((CreateRecGS*)pblock)

        if (pcount >= 2) {
            access = pblock->access;
        
        if (pcount >= 3) {
            fileType.fileType = pblock->fileType;
            if (fileType.fileType == DIRECTORY_FILETYPE)
                storageType = directoryFile;
        
        if (pcount >= 4) {
            fileType.auxType = pblock->auxType;
        
        if (pcount >= 5) {
            storageType = pblock->storageType;
            if (storageType <= 0x0003)
                storageType = pblock->storageType = standardFile;
        
        if (pcount >= 6) {
            eof = pblock->eof;
        
        if (pcount >= 7) {
            resourceEOF = pblock->resourceEOF;
        }}}}}}
        
        #undef pblock
    }
    
    /*
     * Validate and convert parameters
     */
    if (access & ~(readEnable | writeEnable | renameEnable |
        destroyEnable | backupNeeded | fileInvisible))
        return paramRangeErr;
    if (storageType != standardFile && storageType != extendedFile
        && storageType != directoryFile && storageType != extendExistingFile)
        return paramRangeErr;

    if (storageType == directoryFile)
        fileType.fileType = DIRECTORY_FILETYPE;

    attributes = GetFileAttributes(access, storageType == directoryFile);

    // Ensure we have write access initially, even if file will be read-only.
    // This is needed so we can set up the file.
    initialAttributes = attributes & ~(uint32_t)FILE_ATTRIBUTE_READONLY;
    if (initialAttributes == 0)
        initialAttributes = FILE_ATTRIBUTE_NORMAL;

    if (createDateTime.date != 0 || createDateTime.time != 0)
        creationTime = ProDOSTimeToFiletime(createDateTime, dib->session);

    if (storageType != extendExistingFile) {
        /*
         * Create file
         */
        createRequest.SecurityFlags = 0;
        createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
        createRequest.ImpersonationLevel = Impersonation;
        createRequest.SmbCreateFlags = 0;
        createRequest.Reserved = 0;
        createRequest.NameOffset =
            sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
        createRequest.CreateContextsOffset = 0;
        createRequest.CreateContextsLength = 0;
        
        if (storageType == extendExistingFile) {
            createRequest.CreateDisposition = FILE_OPEN;
            createRequest.FileAttributes = 0;
        } else {
            createRequest.CreateDisposition = FILE_CREATE;
            createRequest.FileAttributes = initialAttributes;
        }
    
        if (storageType == directoryFile) {
            createRequest.CreateOptions = FILE_DIRECTORY_FILE;
        } else {
            createRequest.CreateOptions = FILE_NON_DIRECTORY_FILE;
        }
    
        createRequest.DesiredAccess =
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE;
        createRequest.ShareAccess = FILE_SHARE_DELETE;
    
        // translate filename to SMB format
        createRequest.NameLength = GSPathToSMB(gsosdp, 1, createRequest.Buffer,
            sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
        if (createRequest.NameLength == 0xFFFF)
            return badPathSyntax;

        msgLen = sizeof(createRequest) + createRequest.NameLength;

        if (eof != 0) {
            if (storageType == standardFile || storageType == extendedFile) {
                AddCreateContext(SMB2_CREATE_ALLOCATION_SIZE, &eof,
                    sizeof(eof), &msgLen);
                // ignore errors (allocation size isn't very important)
            }
        }
    
        result = SendRequestAndGetResponse(dib->session, SMB2_CREATE,
            dib->treeId, msgLen);
        if (result != rsDone) {
            retval = ConvertError(result);
            if (retval == fileNotFound)
                retval = pathNotFound;
            return retval;
        }
        
        fileID = createResponse.FileId;
    }

    if (storageType == extendedFile || storageType == extendExistingFile) {
        /*
         * Create resource fork
         */
        createRequest.SecurityFlags = 0;
        createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
        createRequest.ImpersonationLevel = Impersonation;
        createRequest.SmbCreateFlags = 0;
        createRequest.Reserved = 0;
        createRequest.NameOffset =
            sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
        createRequest.CreateContextsOffset = 0;
        createRequest.CreateContextsLength = 0;
        
        if (storageType == extendedFile) {
            createRequest.CreateDisposition = FILE_OPEN_IF;
        } else {
            createRequest.CreateDisposition = FILE_CREATE;
        }
        
        
        createRequest.CreateOptions = FILE_NON_DIRECTORY_FILE;
        createRequest.FileAttributes = initialAttributes;
        createRequest.DesiredAccess =
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES;
        createRequest.ShareAccess = FILE_SHARE_DELETE;

        // translate filename to SMB format
        createRequest.NameLength = GSPathToSMB(gsosdp, 1, createRequest.Buffer,
            sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
        if (createRequest.NameLength == 0xFFFF) {
            retval = badPathSyntax;
            goto close_on_error;
        }

        // add resource fork suffix
        if (createRequest.NameLength >
            sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer)
            - sizeof(resourceForkSuffix))
            return badPathSyntax;
        memcpy(createRequest.Buffer + createRequest.NameLength,
            resourceForkSuffix, sizeof(resourceForkSuffix));
        createRequest.NameLength += sizeof(resourceForkSuffix);

        msgLen = sizeof(createRequest) + createRequest.NameLength;

        if (resourceEOF != 0) {
            AddCreateContext(SMB2_CREATE_ALLOCATION_SIZE, &resourceEOF,
                sizeof(resourceEOF), &msgLen);
            // ignore errors (allocation size isn't very important)
        }

        result = SendRequestAndGetResponse(dib->session, SMB2_CREATE,
            dib->treeId, msgLen);
        if (result != rsDone) {
            if (storageType == extendExistingFile
                && result == rsFailed
                && msg.smb2Header.Status == STATUS_OBJECT_NAME_COLLISION) {
                retval = resExistsErr;
            } else {
                retval = ConvertError(result);
            }
            goto close_on_error;
        }

        closeRequest.Flags = 0;
        closeRequest.Reserved = 0;
        closeRequest.FileId = createResponse.FileId;
    
        result = SendRequestAndGetResponse(dib->session, SMB2_CLOSE,
            dib->treeId, sizeof(closeRequest));
        if (result != rsDone) {
            retval = ConvertError(result);
            goto close_on_error;
        }
    }

    if (storageType != extendExistingFile) {
        /*
         * Create and set AFP Info
         */
        createRequest.SecurityFlags = 0;
        createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
        createRequest.ImpersonationLevel = Impersonation;
        createRequest.SmbCreateFlags = 0;
        createRequest.Reserved = 0;
        createRequest.NameOffset =
            sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
        createRequest.CreateContextsOffset = 0;
        createRequest.CreateContextsLength = 0;
        createRequest.CreateDisposition = FILE_OPEN_IF;
        createRequest.CreateOptions = FILE_NON_DIRECTORY_FILE;
        createRequest.FileAttributes = initialAttributes;
        createRequest.DesiredAccess =
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES;
        createRequest.ShareAccess = FILE_SHARE_DELETE;

        // translate filename to SMB format
        createRequest.NameLength = GSPathToSMB(gsosdp, 1, createRequest.Buffer,
            sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
        if (createRequest.NameLength == 0xFFFF) {
            retval = badPathSyntax;
            goto close_on_error;
        }

        // add AFP Info suffix
        if (createRequest.NameLength >
            sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer)
            - sizeof(afpInfoSuffix))
            return badPathSyntax;
        memcpy(createRequest.Buffer + createRequest.NameLength,
            afpInfoSuffix, sizeof(afpInfoSuffix));
        createRequest.NameLength += sizeof(afpInfoSuffix);

        result = SendRequestAndGetResponse(dib->session, SMB2_CREATE,
            dib->treeId, sizeof(createRequest) + createRequest.NameLength);
        if (result != rsDone) {
            // TODO add option to ignore errors setting AFP info
            retval = ConvertError(result);
            goto close_on_error;
        }

        infoFileID = createResponse.FileId;

        /*
         * Create and save AFP Info record (including Finder Info)
         */
        writeRequest.DataOffset =
            sizeof(SMB2Header) + offsetof(SMB2_WRITE_Request, Buffer);
        writeRequest.Length = sizeof(AFPInfo);
        writeRequest.Offset = 0;
        writeRequest.FileId = infoFileID;
        writeRequest.Channel = 0;
        writeRequest.RemainingBytes = 0;
        writeRequest.WriteChannelInfoOffset = 0;
        writeRequest.WriteChannelInfoLength = 0;
        writeRequest.Flags = 0;

#define afpInfo ((AFPInfo*)writeRequest.Buffer)
        memset(afpInfo, 0, sizeof(AFPInfo));
        afpInfo->signature = AFPINFO_SIGNATURE;
        afpInfo->version = AFPINFO_VERSION;
        afpInfo->backupTime = 0x80000000; // indicating "never backed up"
        afpInfo->prodosType = fileType.fileType;
        afpInfo->prodosAuxType = fileType.auxType;
        if (storageType != directoryFile)
            afpInfo->finderInfo.typeCreator =
                FileTypeToTypeCreator(fileType, NULL);
#undef afpInfo

        result = SendRequestAndGetResponse(dib->session, SMB2_WRITE,
            dib->treeId, sizeof(writeRequest) + sizeof(AFPInfo));
        if (result != rsDone)
            retval = ConvertError(result);

        closeRequest.Flags = 0;
        closeRequest.Reserved = 0;
        closeRequest.FileId = infoFileID;
    
        result = SendRequestAndGetResponse(dib->session, SMB2_CLOSE,
            dib->treeId, sizeof(closeRequest));
        if (result != rsDone)
            retval = retval ? retval : ConvertError(result);
        
        if (retval != 0)
            goto close_on_error;
        
        if (attributes != initialAttributes || creationTime != 0) {
            /*
             * Set final attributes and creation time
             */
            setInfoRequest.InfoType = SMB2_0_INFO_FILE;
            setInfoRequest.FileInfoClass = FileBasicInformation;
            setInfoRequest.BufferLength = sizeof(FILE_BASIC_INFORMATION);
            setInfoRequest.BufferOffset =
                sizeof(SMB2Header) + offsetof(SMB2_SET_INFO_Request, Buffer);
            setInfoRequest.Reserved = 0;
            setInfoRequest.AdditionalInformation = 0;
            setInfoRequest.FileId = fileID;
#define info ((FILE_BASIC_INFORMATION *)setInfoRequest.Buffer)
            info->CreationTime = creationTime;
            info->LastAccessTime = 0;
            info->LastWriteTime = 0;
            info->ChangeTime = 0;
            info->FileAttributes = attributes;
            info->Reserved = 0;
#undef info
        
            result = SendRequestAndGetResponse(
                dib->session, SMB2_SET_INFO, dib->treeId, 
                sizeof(setInfoRequest) + sizeof(FILE_BASIC_INFORMATION));
            if (result != rsDone) {
                retval = ConvertError(result);
                goto close_on_error;
            }
        }
    }

close_on_error:
    if (storageType != extendExistingFile) {
        if (retval != 0) {
            /*
             * Put file in delete-pending state if there was an error
             */
            setInfoRequest.InfoType = SMB2_0_INFO_FILE;
            setInfoRequest.FileInfoClass = FileDispositionInformation;
            setInfoRequest.BufferLength = sizeof(FILE_DISPOSITION_INFORMATION);
            setInfoRequest.BufferOffset =
                sizeof(SMB2Header) + offsetof(SMB2_SET_INFO_Request, Buffer);
            setInfoRequest.Reserved = 0;
            setInfoRequest.AdditionalInformation = 0;
            setInfoRequest.FileId = fileID;
#define info ((FILE_DISPOSITION_INFORMATION *)setInfoRequest.Buffer)
            info->DeletePending = 1;
#undef info
        
            SendRequestAndGetResponse(dib->session, SMB2_SET_INFO, dib->treeId,
                sizeof(setInfoRequest) + sizeof(FILE_DISPOSITION_INFORMATION));
            // Ignore errors here (we already have an error to report)
        }

        closeRequest.Flags = 0;
        closeRequest.Reserved = 0;
        closeRequest.FileId = fileID;
    
        SendRequestAndGetResponse(dib->session, SMB2_CLOSE,
            dib->treeId, sizeof(closeRequest));
        // Ignore errors here (file is already created, or already have error)
    }

    return retval;
}
