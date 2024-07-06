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

Word Destroy(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    ReadStatus result;
    DIB *dib;
    SMB2_SET_INFO_Request *setInfoReq;
    Word retval = 0;
    uint16_t createMsgNum, setInfoMsgNum, closeMsgNum;

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

    createMsgNum = EnqueueRequest(dib, SMB2_CREATE,
        sizeof(createRequest) + createRequest.NameLength);

    /*
     * Put file in delete-pending state
     */
    setInfoReq = (SMB2_SET_INFO_Request*)nextMsg->Body;
    if (!SpaceAvailable(
        sizeof(*setInfoReq) + sizeof(FILE_DISPOSITION_INFORMATION)))
        return fstError;

    setInfoReq->InfoType = SMB2_0_INFO_FILE;
    setInfoReq->FileInfoClass = FileDispositionInformation;
    setInfoReq->BufferLength = sizeof(FILE_DISPOSITION_INFORMATION);
    setInfoReq->BufferOffset =
        sizeof(SMB2Header) + offsetof(SMB2_SET_INFO_Request, Buffer);
    setInfoReq->Reserved = 0;
    setInfoReq->AdditionalInformation = 0;
    setInfoReq->FileId = fileIDFromPrevious;
#define info ((FILE_DISPOSITION_INFORMATION *)setInfoReq->Buffer)
    info->DeletePending = 1;
#undef info

    setInfoMsgNum = EnqueueRequest(dib, SMB2_SET_INFO,
        sizeof(*setInfoReq) + sizeof(FILE_DISPOSITION_INFORMATION));

    /*
     * Close file
     */
    closeMsgNum = EnqueueCloseRequest(dib, &fileIDFromPrevious);
    if (closeMsgNum == 0xFFFF)
        return fstError;
    
    SendMessages(dib);

    result = GetResponse(dib, createMsgNum);
    if (result != rsDone)
        retval = ConvertError(result);
    
    result = GetResponse(dib, setInfoMsgNum);
    if (result != rsDone && retval == 0)
        retval = ConvertError(result);
    
    result = GetResponse(dib, closeMsgNum);
    if (result != rsDone && retval == 0)
        retval = ConvertError(result);

    return retval;
}
