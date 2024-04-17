#include "defs.h"
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <gsos.h>
#include "smb2.h"
#include "aapl.h"
#include "fstspecific.h"
#include "driver.h"
#include "gsosutils.h"
#include "helpers/createcontext.h"

#ifndef devListFull
#define devListFull 0x0068
#endif

Word SMB_Mount(SMBMountRec *pblock, void *gsosdp, Word pcount) {
    // TODO use real volume name
    static struct {
        Word len;
        char str[10];
    } volName = {7, "testvol"};

    static ReadStatus result;
    unsigned dibIndex;
    bool oom;
    VirtualPointer vcrVP;
    VCR *vcr;
    Session *session = (Session*)pblock->sessionID;
    uint16_t msgLen;
    uint16_t dataLen;
    AAPL_SERVER_QUERY_RESPONSE *aaplResponse;
    static SMB2_FILEID fileID;

    if (pblock->pCount != 6)
        return invalidPcount;

    for (dibIndex = 0; dibIndex < NDIBS; dibIndex++) {
        if (dibs[dibIndex].extendedDIBPtr == 0)
            break;
    }
    if (dibIndex == NDIBS)
        return devListFull;

    treeConnectRequest.Reserved = 0;
    treeConnectRequest.PathOffset =
        sizeof(SMB2Header) + offsetof(SMB2_TREE_CONNECT_Request, Buffer);
    treeConnectRequest.PathLength = pblock->shareNameSize;
    memcpy(treeConnectRequest.Buffer, pblock->shareName, pblock->shareNameSize);
    
    result = SendRequestAndGetResponse(session, SMB2_TREE_CONNECT, 0,
        sizeof(treeConnectRequest) + pblock->shareNameSize);
    if (result != rsDone) {
        return networkError;
    }

    asm {
        stz oom
        phd
        lda gsosdp
        tcd
        lda #sizeof(VCR)
        ldx #volName
        ldy #^volName
        jsl ALLOC_VCR
        pld
        stx vcrVP
        sty vcrVP+2
        rol oom
    }
    
    if (oom) {
        /*
         * If we're here, VCR allocation failed because we are out of memory.
         * We should probably send a TREE_DISCONNECT message to the server,
         * but we currently don't.  There is a risk that Marinetti may not
         * work right if it cannot allocate memory.
         */
        return outOfMem;
    }

    dibs[dibIndex].treeId = msg.smb2Header.TreeId;
    dibs[dibIndex].switched = true;
    dibs[dibIndex].extendedDIBPtr = &dibs[dibIndex].treeId;
    dibs[dibIndex].vcrVP = vcrVP;
    dibs[dibIndex].session = session;
    dibs[dibIndex].flags = 0;

    DerefVP(vcr, vcrVP);

    vcr->status = 0;
    vcr->openCount = 0;
    vcr->fstID = smbFSID;
    vcr->devNum = dibs[dibIndex].DIBDevNum;

    /*
     * Try to open root directory with AAPL create context
     */
    createRequest.SecurityFlags = 0;
    createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    createRequest.ImpersonationLevel = Impersonation;
    createRequest.SmbCreateFlags = 0;
    createRequest.Reserved = 0;
    createRequest.DesiredAccess = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    createRequest.FileAttributes = 0;
    createRequest.ShareAccess =
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    createRequest.CreateDisposition = FILE_OPEN;
    createRequest.CreateOptions = FILE_DIRECTORY_FILE;
    createRequest.NameOffset =
        sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
    createRequest.NameLength = 0;
    createRequest.CreateContextsOffset = 0;
    createRequest.CreateContextsLength = 0;
    msgLen = sizeof(createRequest);
    
    static const AAPL_SERVER_QUERY_REQUEST aaplContext = {
        .CommandCode = kAAPL_SERVER_QUERY,
        .Reserved = 0,
        .RequestBitmap =
            kAAPL_SERVER_CAPS | kAAPL_VOLUME_CAPS| kAAPL_MODEL_INFO,
        .ClientCapabilities = kAAPL_SUPPORTS_READ_DIR_ATTR,
    };

    AddCreateContext(SMB2_CREATE_AAPL, &aaplContext,
        sizeof(AAPL_SERVER_QUERY_REQUEST), &msgLen);

    result = SendRequestAndGetResponse(
        session, SMB2_CREATE, dibs[dibIndex].treeId, msgLen);
    if (result != rsDone) {
        // TODO better error handling
        goto finish;
    }

    fileID = createResponse.FileId;

    /*
     * Process AAPL response, if provided.
     */
    aaplResponse = GetCreateContext(SMB2_CREATE_AAPL, &dataLen);
    
    if (aaplResponse == NULL || dataLen < sizeof(AAPL_SERVER_QUERY_RESPONSE))
        goto close;

    if (aaplResponse->CommandCode != kAAPL_SERVER_QUERY)
        goto close;
    if (aaplResponse->ReplyBitmap 
        & (kAAPL_SERVER_CAPS | kAAPL_VOLUME_CAPS| kAAPL_MODEL_INFO)
        != (kAAPL_SERVER_CAPS | kAAPL_VOLUME_CAPS| kAAPL_MODEL_INFO))
        goto close;
    
    if (aaplResponse->ServerCapabilities & kAAPL_SUPPORTS_READ_DIR_ATTR)
        dibs[dibIndex].flags |= FLAG_AAPL_READDIR;

close:
    /*
     * Close file
     */
    closeRequest.Flags = 0;
    closeRequest.Reserved = 0;
    closeRequest.FileId = fileID;

    result = SendRequestAndGetResponse(session, SMB2_CLOSE,
        dibs[dibIndex].treeId, sizeof(closeRequest));
    // ignore any errors here

finish:
    pblock->devNum = dibs[dibIndex].DIBDevNum;
    
    Session_Retain(session);
    return 0;
}
