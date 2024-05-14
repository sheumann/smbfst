#include "defs.h"
#include <stddef.h>
#include <string.h>
#include <gsos.h>
#include "smb2/smb2.h"
#include "smb2/aapl.h"
#include "smb2/treeconnect.h"
#include "helpers/createcontext.h"
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "helpers/path.h"
#include "helpers/afpinfo.h"
#include "fstops/Open.h"

Word TreeConnect(DIB *dib) {
    ReadStatus result;
    uint16_t msgLen;
    uint16_t dataLen;
    AAPL_SERVER_QUERY_RESPONSE *aaplResponse;
    static SMB2_FILEID fileID;

    treeConnectRequest.Reserved = 0;
    treeConnectRequest.PathOffset =
        sizeof(SMB2Header) + offsetof(SMB2_TREE_CONNECT_Request, Buffer);
    treeConnectRequest.PathLength = dib->shareNameSize;
    memcpy(treeConnectRequest.Buffer, dib->shareName, dib->shareNameSize);

    result = SendRequestAndGetResponse(dib, SMB2_TREE_CONNECT,
        sizeof(treeConnectRequest) + dib->shareNameSize);
    if (result != rsDone) {
        return networkError;
    }
    
    dib->treeId = msg.smb2Header.TreeId;
    
    dib->flags = 0;

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
        dib->flags |= FLAG_READONLY;

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
            SendRequestAndGetResponse(dib, SMB2_CREATE, msgLen);
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
            dib->flags |= FLAG_AAPL_READDIR;
    
close:
        /*
         * Close file
         */
        closeRequest.Flags = 0;
        closeRequest.Reserved = 0;
        closeRequest.FileId = fileID;
    
        result = SendRequestAndGetResponse(dib, SMB2_CLOSE,
            sizeof(closeRequest));
        // ignore any errors here
    } else if (treeConnectResponse.ShareType == SMB2_SHARE_TYPE_PIPE) {
        dib->flags |= FLAG_PIPE_SHARE;
    }

finish:
    return 0;
}

static void ReconnectFile(DIB *dib, FCR *fcr) {
    VirtualPointer vp;
    GSString *path;

    /*
     * Re-open file
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
    
    if (fcr->access & ACCESS_FLAG_RFORK) {
        createRequest.CreateDisposition = FILE_OPEN_IF;
    } else {
        createRequest.CreateDisposition = FILE_OPEN;
    }

    // translate filename to SMB format
    vp = fcr->pathName;
    DerefVP(path, vp);
    createRequest.NameLength = GSPathToSMB(path, createRequest.Buffer,
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
    if (createRequest.NameLength == 0xFFFF)
        return;

    if (fcr->access & ACCESS_FLAG_RFORK) {
        if (createRequest.NameLength >
            sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer)
            - sizeof(resourceForkSuffix))
            return;
        memcpy(createRequest.Buffer + createRequest.NameLength,
            resourceForkSuffix, sizeof(resourceForkSuffix));
        createRequest.NameLength += sizeof(resourceForkSuffix);
    }

    SetOpenAccess(fcr->access & (readEnable | writeEnable),
        (bool)(fcr->smbFlags & SMB_FLAG_P16SHARING));
    
    if (SendRequestAndGetResponse(dib, SMB2_CREATE,
        sizeof(createRequest) + createRequest.NameLength) != rsDone)
        return;

    /*
     * Check if the creation time matches as a heuristic to determine if this
     * is the same file that was open previously.  This heuristic can have
     * false positives and false negatives, but it should work in most cases.
     */
    if (createResponse.CreationTime != fcr->createTime) {
        /*
         * Close file if it seems to be a different file
         */
        closeRequest.Flags = 0;
        closeRequest.Reserved = 0;
        closeRequest.FileId = createResponse.FileId;
    
        SendRequestAndGetResponse(dib, SMB2_CLOSE, sizeof(closeRequest));
        
        return;
    }

    /*
     * Update file ID in message that will be retried, if applicable.
     */
    if (dib == reconnectInfo.dib && reconnectInfo.fileId != NULL
        && memcmp(reconnectInfo.fileId, &fcr->fileID, sizeof(SMB2_FILEID)) == 0)
    {
        *reconnectInfo.fileId = createResponse.FileId;
        reconnectInfo.fileId = NULL;
    }
    
    fcr->fileID = createResponse.FileId;
    fcr->eof = createResponse.EndofFile;
}

Word TreeConnect_Reconnect(DIB *dib) {
    VirtualPointer vp;
    VCR *vcr;
    FCR *fcr;
    Word result;
    unsigned i;
    bool done;
    
    result = TreeConnect(dib);
    if (result != 0)
        return result;
    
    result = GetVCR(dib, &vcr);
    if (result != 0)
        return result;

    if (vcr->openCount != 0) {
        for (i = 1, done = false; ; i++) {
            asm {
                ldx i
                phd
                lda gsosDP
                tcd
                txa
                jsl GET_FCR
                pld
                rol done
                stx vp
                sty vp+2
            }
            
            if (done)
                break;
            
            DerefVP(fcr, vp);
            if (fcr->volID == vcr->id && fcr->fstID == smbFSID) {
                ReconnectFile(dib, fcr);
            }
        }
    }

    return result;
}