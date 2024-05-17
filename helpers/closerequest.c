#include "defs.h"
#include "smb2/smb2.h"
#include "helpers/closerequest.h"

/*
 * Enqueue a request to close the file with the specified file ID.
 * Returns request number on success, or 0xFFFF on failure.
 */
unsigned EnqueueCloseRequest(DIB *dib, const SMB2_FILEID *fileID) {
    SMB2_CLOSE_Request *closeReq;

    closeReq = (SMB2_CLOSE_Request*)nextMsg->Body;
    if (!SpaceAvailable(sizeof(*closeReq)))
        return 0xFFFF;

    closeReq->Flags = 0;
    closeReq->Reserved = 0;
    closeReq->FileId = *fileID;

    return EnqueueRequest(dib, SMB2_CLOSE, sizeof(*closeReq));
}

/*
 * Send a close request as non-compounded message, and get the response.
 */
ReadStatus SendCloseRequestAndGetResponse(DIB *dib, const SMB2_FILEID *fileID) {
    closeRequest.Flags = 0;
    closeRequest.Reserved = 0;
    closeRequest.FileId = *fileID;
    
    return SendRequestAndGetResponse(dib, SMB2_CLOSE, sizeof(closeRequest));
}
