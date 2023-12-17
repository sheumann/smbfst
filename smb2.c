#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <uchar.h>
#include <tcpip.h>
#include <memory.h>
#include <orca.h>

/* for debugging only */
#include <misctool.h>
#include <stdio.h>

#include "defs.h"
#include "connection.h"
#include "endian.h"
#include "smb2proto.h"
#include "smb2.h"
#include "readtcp.h"
#include "auth.h"
#include "crypto/sha256.h"

static const uint16_t requestStructureSizes[] = {
    [SMB2_NEGOTIATE] = 36,
    [SMB2_SESSION_SETUP] = 25,
    [SMB2_LOGOFF] = 4,
    [SMB2_TREE_CONNECT] = 9,
    [SMB2_TREE_DISCONNECT] = 4,
    [SMB2_CREATE] = 57,
    [SMB2_CLOSE] = 24,
    [SMB2_FLUSH] = 24,
    [SMB2_READ] = 49,
    [SMB2_WRITE] = 49,
    [SMB2_LOCK] = 48,
    [SMB2_IOCTL] = 57,
    [SMB2_CANCEL] = 4,
    [SMB2_ECHO] = 4,
    [SMB2_QUERY_DIRECTORY] = 33,
    [SMB2_CHANGE_NOTIFY] = 32,
    [SMB2_QUERY_INFO] = 41,
    [SMB2_SET_INFO] = 33,
    [SMB2_OPLOCK_BREAK] = 24, /* for acknowledgment */
};

/*
 * StructureSize values for response structures.
 *
 * Note: The StructureSize field should always be set to these values,
 * but the actual size of the structure can sometimes be one byte smaller,
 * because the low-order bit of these values represents a variable-length
 * portion of the response, and in some cases that portion can be empty.
 */
static const uint16_t responseStructureSizes[] = {
    [SMB2_NEGOTIATE] = 65,
    [SMB2_SESSION_SETUP] = 9,
    [SMB2_LOGOFF] = 4,
    [SMB2_TREE_CONNECT] = 16,
    [SMB2_TREE_DISCONNECT] = 4,
    [SMB2_CREATE] = 89,
    [SMB2_CLOSE] = 60,
    [SMB2_FLUSH] = 4,
    [SMB2_READ] = 17,
    [SMB2_WRITE] = 17,
    [SMB2_LOCK] = 4,
    [SMB2_IOCTL] = 49,
    [SMB2_CANCEL] = 0, /* no response */
    [SMB2_ECHO] = 4,
    [SMB2_QUERY_DIRECTORY] = 9,
    [SMB2_CHANGE_NOTIFY] = 9,
    [SMB2_QUERY_INFO] = 9,
    [SMB2_SET_INFO] = 2,
    [SMB2_OPLOCK_BREAK] = 24,
};


static const smb_u128 u128_zero = {0,0};

MsgRec msg;

uint16_t bodySize;   // size of last message received

//static ReadStatus result;   // result from last read

ReadStatus ReadMessage(Connection *connection) {
    ReadStatus result;
    uint32_t msgSize;
    
    result = ReadTCP(connection->ipid, 4, &msg.directTCPHeader);
    if (result != rsDone)
        return result;
    
    msgSize = ntoh32(msg.directTCPHeader.StreamProtocolLength);
    if (msgSize > sizeof(SMB2Header) + sizeof(msg.body)) {
        return rsError;
    }
    
    result = ReadTCP(connection->ipid, msgSize, &msg.smb2Header);
    if (result != rsDone)
        return result;

    // Check that it looks like an SMB2/3 message
    
    if (msgSize < sizeof(SMB2Header))
        return rsError;
    if (msg.smb2Header.ProtocolId != 0x424D53FE)
        return rsError;
    if (msg.smb2Header.StructureSize != 64)
        return rsError;
    
    bodySize = msgSize - sizeof(SMB2Header);
    
    return rsDone;
}

bool SendMessage(Connection *connection, uint16_t command, uint32_t treeId,
                 uint16_t bodyLength) {
    Word tcperr;

    msg.smb2Header.ProtocolId = 0x424D53FE;
    msg.smb2Header.StructureSize = 64;
    
    if (connection->dialect == SMB_202) {
        msg.smb2Header.CreditCharge = 0;
    } else {
        UNIMPLEMENTED
    }
    
    if (connection->dialect <= SMB_21) {
        msg.smb2Header.Status = 0;
    } else {
        UNIMPLEMENTED
    }

    msg.smb2Header.Command = command;
    
    msg.smb2Header.CreditRequest = 1;
    
    msg.smb2Header.Flags = 0;
    msg.smb2Header.NextCommand = 0;
    msg.smb2Header.MessageId = connection->nextMessageId++;
    msg.smb2Header.Reserved2 = 0;
    msg.smb2Header.TreeId = treeId;
    msg.smb2Header.SessionId = connection->sessionId;
    msg.smb2Header.Signature = u128_zero;

    if (connection->signingRequired) {
        msg.smb2Header.Flags |= SMB2_FLAGS_SIGNED;
        
        hmac_sha256_compute(connection->signingContext, (void*)&msg.smb2Header,
            sizeof(SMB2Header) + bodyLength);
        memcpy(&msg.smb2Header.Signature,
            connection->signingContext->u[0].ctx.hash, 16);
    }
    
    msg.directTCPHeader.StreamProtocolLength =
        hton32(sizeof(SMB2Header) + bodyLength);

    tcperr =
        TCPIPWriteTCP(connection->ipid, (void*)&msg,
                      4 + sizeof(SMB2Header) + bodyLength, TRUE, FALSE);
    return !(tcperr || toolerror());
}

ReadStatus SendRequestAndGetResponse(Connection *connection, uint16_t command,
                                     uint32_t treeId, uint16_t bodyLength) {
    uint64_t messageId = connection->nextMessageId;
    
    msgBodyHeader.StructureSize = requestStructureSizes[command];
    
    if (SendMessage(connection, command, treeId, bodyLength) == false)
        return rsError;

    if (ReadMessage(connection) != rsDone)
        return rsError;
    
    // Check that the message received is a response to the one sent.
    if (!(msg.smb2Header.Flags & SMB2_FLAGS_SERVER_TO_REDIR))
        return rsError;
    if (msg.smb2Header.MessageId != messageId)
        return rsError;
    if (msg.smb2Header.Command != command)
        return rsError;
    
    if (bodySize < (responseStructureSizes[command] & 0xFFFE))
        return rsError;
    if (msgBodyHeader.StructureSize != responseStructureSizes[command])
        return rsError;

    if (msg.smb2Header.Status == STATUS_SUCCESS) {
        return rsDone;
    } else if (msg.smb2Header.Status == STATUS_MORE_PROCESSING_REQUIRED) {
        return rsMoreProcessingRequired;
    } else {
        // TODO handle errors
        return rsError;
    }
}

#if 0
void Negotiate(Connection *connection) {
    // assume lowest version until we have negotiated
    connection->dialect = SMB_202;

    negotiateRequest.DialectCount = 1;
    negotiateRequest.SecurityMode = 0;
    negotiateRequest.Reserved = 0;
    negotiateRequest.Capabilities = 0;
    
    // TODO generate real GUID
    negotiateRequest.ClientGuid = (smb_u128){0xa248283946289746,0xac65879365873456};
    
    negotiateRequest.ClientStartTime = 0;
    
    negotiateRequest.Dialects[0] = SMB_202;
    negotiateRequest.Dialects[1] = 0;
    negotiateRequest.Dialects[2] = 0;
    negotiateRequest.Dialects[3] = 0;
    
    result = SendRequestAndGetResponse(connection, SMB2_NEGOTIATE, 0,
        sizeof(negotiateRequest) + 4*sizeof(negotiateRequest.Dialects[0]));
    if (result != rsDone) {
        // TODO handle errors
        return;
    }
    
    connection->wantSigning =
        negotiateResponse.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED;
        
    if (negotiateResponse.DialectRevision != SMB_202) {
        // TODO handle other dialects, and handle errors
        return;
    }
    connection->dialect = negotiateResponse.DialectRevision;
    
    if (negotiateResponse.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED) {
        connection->wantSigning = true;
    }
    
    // TODO compute time difference based on negotiateResponse.SystemTime
    
    // Security buffer is currently ignored
}

void SessionSetup(Connection *connection) {
    static AuthState authState;
    static size_t authSize;
    static unsigned char *previousAuthMsg;
    static size_t previousAuthSize;
    
    InitAuth(&authState);
    previousAuthMsg = NULL;
    previousAuthSize = 0;

    while (1) {
        authSize = DoAuthStep(&authState, previousAuthMsg,
            previousAuthSize, sessionSetupRequest.Buffer);
        if (authSize == (size_t)-1) {
            // TODO handle errors
            break;
        }

        sessionSetupRequest.Flags = 0;
        sessionSetupRequest.SecurityMode = 0;
        sessionSetupRequest.Capabilities = 0;
        sessionSetupRequest.Channel = 0;
        sessionSetupRequest.SecurityBufferOffset = 
            sizeof(SMB2Header) + sizeof(SMB2_SESSION_SETUP_Request);
        sessionSetupRequest.SecurityBufferLength = authSize;
        sessionSetupRequest.PreviousSessionId = 0;
    
        result = SendRequestAndGetResponse(connection, SMB2_SESSION_SETUP, 0,
            sizeof(sessionSetupRequest) + authSize);
        
        if (result == rsDone) {
            if (connection->wantSigning &&
                (sessionSetupResponse.SessionFlags &
                    (SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL)) == 0)
            {
                if (connection->dialect <= SMB_21) {
                    Handle ctxHandle = NewHandle(
                        sizeof(struct hmac_sha256_context), userid(), 0x8015, 0);
                    if (toolerror()) {
                        // TODO handle errors
                        return;
                    }
                
                    connection->signingRequired = true;
                    connection->signingContext = (void*)*ctxHandle;
                
                    hmac_sha256_init(connection->signingContext,
                        authState.signKey,
                        16);
                } else {
                    // TODO SMB 3.x version
                    UNIMPLEMENTED
                }
            }
        
            return;
        } else if (result != rsMoreProcessingRequired) {
            // TODO handle errors
            return;
        }

        if (!VerifyBuffer(
            sessionSetupResponse.SecurityBufferOffset,
            sessionSetupResponse.SecurityBufferLength)) {
            // TODO handle errors
            
            printf("Security Buffer Offset = %u, SecurityBuffer Length = %u, exceeds body size of %u\n",
                sessionSetupResponse.SecurityBufferOffset,
                sessionSetupResponse.SecurityBufferLength,
                bodySize);
            return;
        }
        
        connection->sessionId = msg.smb2Header.SessionId;
        
        previousAuthMsg = (unsigned char *)&msg.smb2Header + 
            sessionSetupResponse.SecurityBufferOffset;
        previousAuthSize = sessionSetupResponse.SecurityBufferLength;
    };
}

uint32_t TreeConnect(Connection *connection, char16_t share[],
    uint16_t shareSize) {
    treeConnectRequest.Reserved = 0;
    treeConnectRequest.PathOffset =
        sizeof(SMB2Header) + offsetof(SMB2_TREE_CONNECT_Request, Buffer);
    treeConnectRequest.PathLength = shareSize;
    memcpy(treeConnectRequest.Buffer, share, shareSize);
    
    result = SendRequestAndGetResponse(connection, SMB2_TREE_CONNECT, 0,
        sizeof(treeConnectRequest) + shareSize);
    if (result != rsDone) {
        // TODO handle errors
        return 0;
    }
    
    // TODO check if 0 could be a valid treeId; if so, distinguish error returns
    return msg.smb2Header.TreeId;
}

SMB2_FILEID Open(Connection *connection, uint32_t treeId,
    char16_t file[], uint16_t fileSize) {
    
    createRequest.SecurityFlags = 0;
    createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    createRequest.ImpersonationLevel = Impersonation;
    createRequest.SmbCreateFlags = 0;
    createRequest.Reserved = 0;
    createRequest.DesiredAccess = FILE_READ_DATA; // TODO allow to configure
    createRequest.FileAttributes = 0;
    createRequest.ShareAccess = 0; // TODO set based on desired access
    createRequest.CreateDisposition = FILE_OPEN;
    createRequest.CreateOptions = 0;
    createRequest.NameOffset =
        sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
    createRequest.NameLength = fileSize;
    createRequest.CreateContextsOffset = 0;
    createRequest.CreateContextsLength = 0;
    memcpy(createRequest.Buffer, file, fileSize);

    result = SendRequestAndGetResponse(connection, SMB2_CREATE, treeId,
        sizeof(createRequest) + fileSize);
    if (result != rsDone) {
        // TODO handle errors
        return (SMB2_FILEID){0,0};
    }
    
    return createResponse.FileId;
}

uint32_t Read(Connection *connection, uint32_t treeId, SMB2_FILEID file,
    uint64_t offset, uint16_t length, void *buf) {

    readRequest.Padding = 0;
    readRequest.Flags = 0;
    readRequest.Length = length;
    readRequest.Offset = offset;
    readRequest.FileId = file;
    readRequest.MinimumCount = 1; // TODO check if this is appropriate
    readRequest.Channel = 0;
    readRequest.RemainingBytes = 0;
    readRequest.ReadChannelInfoOffset = 0;
    readRequest.ReadChannelInfoLength = 0;
    
    result = SendRequestAndGetResponse(connection, SMB2_READ, treeId,
        sizeof(readRequest));
    if (result != rsDone) {
        // TODO handle errors
        return 0;
    }
    
    // TODO verify that data area specified by offset/length is in bounds
    memcpy(buf, (char*)&msg.smb2Header + readResponse.DataOffset,
        readResponse.DataLength);
    
    return readResponse.DataLength;
}

void Close(Connection *connection, uint32_t treeId, SMB2_FILEID file) {
    closeRequest.Flags = 0;
    closeRequest.Reserved = 0;
    closeRequest.FileId = file;

    result = SendRequestAndGetResponse(connection, SMB2_CLOSE, treeId,
        sizeof(closeRequest));
    if (result != rsDone) {
        // TODO handle errors
        return;
    }
}

uint16_t QueryDirectory(Connection *connection, uint32_t treeId,
    SMB2_FILEID file, uint16_t length, void *buf) {

    queryDirectoryRequest.FileInformationClass = FileDirectoryInformation;
    queryDirectoryRequest.Flags = SMB2_RETURN_SINGLE_ENTRY;
    queryDirectoryRequest.FileIndex = 0;
    queryDirectoryRequest.FileId = file;
    queryDirectoryRequest.FileNameOffset =
        sizeof(SMB2Header) + offsetof(SMB2_QUERY_DIRECTORY_Request, Buffer);
    queryDirectoryRequest.FileNameLength = 2;
    queryDirectoryRequest.OutputBufferLength =
        sizeof(msg.body) - sizeof(SMB2_QUERY_DIRECTORY_Response);
        
    /* 
     * Note: [MS-SMB2] says the file name pattern is optional,
     * but Mac (at least) requires it.
     */
    queryDirectoryRequest.Buffer[0] = '*';
    queryDirectoryRequest.Buffer[1] = '\0';

    result = SendRequestAndGetResponse(connection, SMB2_QUERY_DIRECTORY, treeId,
        sizeof(queryDirectoryRequest) + 2);
    if (result != rsDone) {
        // TODO handle errors
        return 0;
    }

    if (queryDirectoryResponse.OutputBufferLength >
        sizeof(msg.body) - sizeof(SMB2_QUERY_DIRECTORY_Response))
        return 0;
    if (queryDirectoryResponse.OutputBufferOffset + 
        queryDirectoryResponse.OutputBufferLength > sizeof(msg))
        return 0;
    if (queryDirectoryResponse.OutputBufferOffset + 
        queryDirectoryResponse.OutputBufferLength <
        sizeof(SMB2Header) + sizeof(queryDirectoryResponse))
        return 0;
    
    uint16_t resultLen = min(length, queryDirectoryResponse.OutputBufferLength);
    memcpy(buf,
        (char*)&msg.smb2Header + queryDirectoryResponse.OutputBufferOffset,
        resultLen);

    return resultLen;
}
#endif
