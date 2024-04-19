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

Word Destroy(void *pblock, void *gsosdp, Word pcount) {
    ReadStatus result;
    DIB *dib;
    SMB2_FILEID fileID;
    Word retval = 0;

    dib = GetDIB(gsosdp, 1);
    if (dib == NULL)
        return volNotFound;
    
    /*
     * Open file
     */
    createRequest.SecurityFlags = 0;
    createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    createRequest.ImpersonationLevel = Impersonation;
    createRequest.SmbCreateFlags = 0;
    createRequest.Reserved = 0;
    createRequest.DesiredAccess = DELETE;
    createRequest.FileAttributes = 0;
    createRequest.ShareAccess = 0;
    createRequest.CreateDisposition = FILE_OPEN;
    createRequest.CreateOptions = 0;
    createRequest.NameOffset =
        sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
    createRequest.CreateContextsOffset = 0;
    createRequest.CreateContextsLength = 0;

    // translate filename to SMB format
    createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1, createRequest.Buffer,
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
    if (createRequest.NameLength == 0xFFFF)
        return badPathSyntax;

    result = SendRequestAndGetResponse(dib->session, SMB2_CREATE, dib->treeId,
        sizeof(createRequest) + createRequest.NameLength);
    if (result != rsDone)
        return ConvertError(result);
    
    fileID = createResponse.FileId;

    /*
     * Put file in delete-pending state
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

    result = SendRequestAndGetResponse(dib->session, SMB2_SET_INFO, dib->treeId,
        sizeof(setInfoRequest) + sizeof(FILE_DISPOSITION_INFORMATION));
    if (result != rsDone)
        retval = ConvertError(result);

    /*
     * Close file
     */
    closeRequest.Flags = 0;
    closeRequest.Reserved = 0;
    closeRequest.FileId = fileID;

    result = SendRequestAndGetResponse(dib->session, SMB2_CLOSE, dib->treeId,
        sizeof(closeRequest));
    if (result != rsDone)
        return retval ? retval : ConvertError(result);

    return retval;
}
