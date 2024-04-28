#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "smb2/smb2.h"
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "smb2/fileinfo.h"
#include "helpers/path.h"
#include "utils/endian.h"
#include "fst/fstspecific.h"
#include "helpers/filetype.h"
#include "helpers/datetime.h"
#include "helpers/attributes.h"
#include "helpers/errors.h"
#include "helpers/createcontext.h"

#define extendExistingFile 0x8005

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
        createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1,
            createRequest.Buffer,
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
    
        result = SendRequestAndGetResponse(dib, SMB2_CREATE, msgLen);
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
        createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1,
            createRequest.Buffer,
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

        result = SendRequestAndGetResponse(dib, SMB2_CREATE, msgLen);
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
    
        result = SendRequestAndGetResponse(dib, SMB2_CLOSE,
            sizeof(closeRequest));
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
        createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1, 
            createRequest.Buffer,
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

        result = SendRequestAndGetResponse(dib, SMB2_CREATE,
            sizeof(createRequest) + createRequest.NameLength);
        if (result != rsDone) {
            /*
             * If we get STATUS_OBJECT_NAME_INVALID for the AFP info (after
             * successfully creating the main stream with the same base name),
             * this presumably means that the filesystem does not support
             * named streams.  We will not report this as an error, because
             * if we did it would prevent us from creating files on such
             * filesystems at all.  This way, we can at least create files,
             * although the filetype and Finder Info will not be set correctly.
             */
            if (result == rsFailed
                && msg.smb2Header.Status == STATUS_OBJECT_NAME_INVALID) {
                goto set_attributes;
            } else {
                retval = ConvertError(result);
                goto close_on_error;
            }
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

        result = SendRequestAndGetResponse(dib, SMB2_WRITE,
            sizeof(writeRequest) + sizeof(AFPInfo));
        if (result != rsDone)
            retval = ConvertError(result);

        closeRequest.Flags = 0;
        closeRequest.Reserved = 0;
        closeRequest.FileId = infoFileID;
    
        result = SendRequestAndGetResponse(dib, SMB2_CLOSE,
            sizeof(closeRequest));
        if (result != rsDone)
            retval = retval ? retval : ConvertError(result);
        
        if (retval != 0)
            goto close_on_error;

set_attributes:
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
        
            result = SendRequestAndGetResponse(dib, SMB2_SET_INFO, 
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
        
            SendRequestAndGetResponse(dib, SMB2_SET_INFO,
                sizeof(setInfoRequest) + sizeof(FILE_DISPOSITION_INFORMATION));
            // Ignore errors here (we already have an error to report)
        }

        closeRequest.Flags = 0;
        closeRequest.Reserved = 0;
        closeRequest.FileId = fileID;
    
        SendRequestAndGetResponse(dib, SMB2_CLOSE, sizeof(closeRequest));
        // Ignore errors here (file is already created, or already have error)
    }

    return retval;
}
