#include "defs.h"
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <gsos.h>
#include "smb2/smb2.h"
#include "smb2/aapl.h"
#include "smb2/treeconnect.h"
#include "fst/fstspecific.h"
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "helpers/createcontext.h"
#include "utils/alloc.h"

Word SMB_Mount(SMBMountRec *pblock, void *gsosdp, Word pcount) {
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
    GSString *volName;
    Word errCode;

    if (pblock->pCount != 7)
        return invalidPcount;

    for (dibIndex = 0; dibIndex < NDIBS; dibIndex++) {
        if (dibs[dibIndex].extendedDIBPtr == 0)
            break;
    }
    if (dibIndex == NDIBS)
        return devListFull;

    dibs[dibIndex].shareName = smb_malloc(pblock->shareNameSize);
    if (dibs[dibIndex].shareName == NULL)
        return outOfMem;
    memcpy(dibs[dibIndex].shareName, pblock->shareName, pblock->shareNameSize);
    dibs[dibIndex].shareNameSize = pblock->shareNameSize;
    dibs[dibIndex].session = session;
    dibs[dibIndex].treeId = 0;
    
    errCode = TreeConnect(&dibs[dibIndex]);
    if (errCode) {
        smb_free(dibs[dibIndex].shareName);
        return errCode;
    }

    volName = pblock->volName;
    asm {
        stz oom
        ldx volName
        ldy volName+2
        phd
        lda gsosdp
        tcd
        lda #sizeof(VCR)
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
        smb_free(dibs[dibIndex].shareName);
        return outOfMem;
    }

    dibs[dibIndex].treeId = msg.smb2Header.TreeId;
    dibs[dibIndex].switched = true;
    dibs[dibIndex].extendedDIBPtr = &dibs[dibIndex].treeId;
    dibs[dibIndex].vcrVP = vcrVP;
    dibs[dibIndex].flags = 0;

    DerefVP(vcr, vcrVP);

    vcr->status = 0;
    vcr->openCount = 0;
    vcr->fstID = smbFSID;
    vcr->devNum = dibs[dibIndex].DIBDevNum;

    /*
     * Flag if the share is read-only.
     * We intentionally do not include DELETE permission in this check,
     * because Samba reports it as enabled even for read-only shares.
     * The absence of the other permissions (including FILE_DELETE_CHILD)
     * should be sufficient to indicate that the share is read-only.
     */
    if ((treeConnectResponse.MaximalAccess & 
        (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD |
        FILE_WRITE_ATTRIBUTES | GENERIC_WRITE)) == 0)
        dibs[dibIndex].flags |= FLAG_READONLY;

    if (treeConnectResponse.ShareType == SMB2_SHARE_TYPE_DISK) {    
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
    
        result = 
            SendRequestAndGetResponse(&dibs[dibIndex], SMB2_CREATE, msgLen);
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
    
        result = SendRequestAndGetResponse(&dibs[dibIndex], SMB2_CLOSE,
            sizeof(closeRequest));
        // ignore any errors here
    } else if (treeConnectResponse.ShareType == SMB2_SHARE_TYPE_PIPE) {
        dibs[dibIndex].flags |= FLAG_PIPE_SHARE;
    }

finish:
    pblock->devNum = dibs[dibIndex].DIBDevNum;
    
    Session_Retain(session);
    return 0;
}
