#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <uchar.h>
#include <stddef.h>
#include <string.h>
#include "smb2/smb2.h"
#include "smb2/fileinfo.h"
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "helpers/path.h"
#include "helpers/errors.h"
#include "helpers/closerequest.h"

Word ChangePath(void *pblock, void *gsosdp, Word pcount) {
    ReadStatus result;
    DIB *dib1, *dib2;
    SMB2_FILEID fileID;
    Word retval = 0;

    dib1 = GetDIB(gsosdp, 1);
    dib2 = GetDIB(gsosdp, 2);
    if (dib1 == NULL || dib2 == NULL)
        return volNotFound;
    if (dib1 != dib2) {
        // trying to move a file to a different volume -- not supported
        return unknownVol;
    }

    /*
     * Open file for rename
     */
    createRequest.SecurityFlags = 0;
    createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    createRequest.ImpersonationLevel = Impersonation;
    createRequest.SmbCreateFlags = 0;
    createRequest.Reserved = 0;
    createRequest.DesiredAccess = DELETE;
    createRequest.FileAttributes = 0;
    createRequest.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
    createRequest.CreateDisposition = FILE_OPEN;
    createRequest.CreateOptions = 0;
    createRequest.NameOffset =
        sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
    createRequest.CreateContextsOffset = 0;
    createRequest.CreateContextsLength = 0;

    // translate filename 1 to SMB format
    createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1, createRequest.Buffer,
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
    if (createRequest.NameLength == 0xFFFF)
        return badPathSyntax;
    if (createRequest.NameLength == 0) {
        // trying to rename the volume -- not supported
        return invalidAccess;
    }

    result = SendRequestAndGetResponse(dib1, SMB2_CREATE,
        sizeof(createRequest) + createRequest.NameLength);
    if (result != rsDone)
        return ConvertError(result);
    
    fileID = createResponse.FileId;
    
    /*
     * Rename file
     */
    setInfoRequest.InfoType = SMB2_0_INFO_FILE;
    setInfoRequest.FileInfoClass = FileRenameInformation;
    setInfoRequest.BufferOffset =
        sizeof(SMB2Header) + offsetof(SMB2_SET_INFO_Request, Buffer);
    setInfoRequest.Reserved = 0;
    setInfoRequest.AdditionalInformation = 0;
    setInfoRequest.FileId = fileID;
#define info ((FILE_RENAME_INFORMATION_TYPE_2 *)setInfoRequest.Buffer)
    info->ReplaceIfExists = 0;
    info->RootDirectory = 0;

    // initialize possible padding bytes (used if name is short)
    info->FileName[0] = 0;
    info->FileName[1] = 0;

    // translate filename 2 to SMB format
    info->FileNameLength = GSOSDPPathToSMB(gsosdp, 2, (uint8_t*)info->FileName,
        sizeof(msg.body)
        - sizeof(setInfoRequest)
        - offsetof(FILE_RENAME_INFORMATION_TYPE_2, FileName));
    if (info->FileNameLength == 0xFFFF) {
        retval = badPathSyntax;
        goto close;
    }

    setInfoRequest.BufferLength =
        sizeof(FILE_RENAME_INFORMATION_TYPE_2) + info->FileNameLength;
    if (setInfoRequest.BufferLength < FILE_RENAME_INFORMATION_TYPE_2_MIN_SIZE)
        setInfoRequest.BufferLength = FILE_RENAME_INFORMATION_TYPE_2_MIN_SIZE;
#undef info
    
    result = SendRequestAndGetResponse(dib1, SMB2_SET_INFO,
        sizeof(setInfoRequest) + setInfoRequest.BufferLength);
    if (result != rsDone)
        retval = ConvertError(result);

close:
    /*
     * Close file
     */
    result = SendCloseRequestAndGetResponse(dib1, &fileID);
    if (result != rsDone)
        return retval ? retval : networkError;

    return retval;
}
