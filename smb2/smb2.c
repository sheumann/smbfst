#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <uchar.h>
#include <tcpip.h>
#include <memory.h>
#include <misctool.h>
#include <orca.h>

#include "defs.h"
#include "smb2/connection.h"
#include "smb2/session.h"
#include "smb2/treeconnect.h"
#include "utils/endian.h"
#include "smb2/smb2proto.h"
#include "smb2/smb2.h"
#include "utils/readtcp.h"
#include "utils/alloc.h"
#include "auth/auth.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"

/*
 * StructureSize values for request structures.
 *
 * The low-order bit represents a variable-length portion of the structure,
 * which can sometimes validly be empty.  However, Windows requires the
 * actual data size to at least match the structure size, so a byte of
 * padding must be included in those cases.
 */
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

/*
 * This will contain the offset of the FileId field in each request
 * structure (or 0 if it is not present).
 */
static uint8_t fileIdOffsets[SMB2_OPLOCK_BREAK + 1];

#define SMB2_ERROR_RESPONSE_STRUCTURE_SIZE 9u

#define MIN_RECONNECT_TIME 5 /* seconds */

static bool Reconnect(DIB *dib, uint16_t bodyLength);

static const smb_u128 u128_zero = {0,0};

MsgRec msg;

uint16_t bodySize;   // size of last message received

ReconnectInfo reconnectInfo;

ReadStatus ReadMessage(Connection *connection) {
    ReadStatus result;
    uint32_t msgSize;
    
    result = ReadTCP(connection, 4, &msg.directTCPHeader);
    if (result != rsDone)
        return result;
    
    msgSize = ntoh32(msg.directTCPHeader.StreamProtocolLength);
    if (msgSize > sizeof(SMB2Header) + sizeof(msg.body)) {
        return rsBadMsg;
    }
    
    result = ReadTCP(connection, msgSize, &msg.smb2Header);
    if (result != rsDone)
        return rsBadMsg;

    // Check that it looks like an SMB2/3 message
    
    if (msgSize < sizeof(SMB2Header))
        return rsBadMsg;
    if (msg.smb2Header.ProtocolId != 0x424D53FE)
        return rsBadMsg;
    if (msg.smb2Header.StructureSize != 64)
        return rsBadMsg;
    
    bodySize = msgSize - sizeof(SMB2Header);
    
    return rsDone;
}

bool SendMessage(Session *session, uint16_t command, uint32_t treeId,
                 uint16_t bodyLength) {
    Connection *connection = session->connection;
    Word tcperr;

    msg.smb2Header.ProtocolId = 0x424D53FE;
    msg.smb2Header.StructureSize = 64;
    
    if (connection->dialect == SMB_202) {
        msg.smb2Header.CreditCharge = 0;
    } else {
        // Our messages are always < 64K, so CreditCharge is just 1.
        msg.smb2Header.CreditCharge = 1;
    }
    
    if (connection->dialect <= SMB_21) {
        msg.smb2Header.Status = 0;
    } else {
        // TODO support reconnection with updated ChannelSequence
        msg.smb2Header.ChannelSequence = 0;
        msg.smb2Header.Reserved = 0;
    }

    msg.smb2Header.Command = command;
    
    msg.smb2Header.CreditRequest = 1;
    
    msg.smb2Header.Flags = 0;
    msg.smb2Header.NextCommand = 0;
    msg.smb2Header.MessageId = connection->nextMessageId++;
    msg.smb2Header.Reserved2 = 0;
    msg.smb2Header.TreeId = treeId;
    msg.smb2Header.SessionId = session->sessionId;
    msg.smb2Header.Signature = u128_zero;

    if (session->signingRequired) {
        msg.smb2Header.Flags |= SMB2_FLAGS_SIGNED;
        
        if (connection->dialect <= SMB_21) {
            hmac_sha256_compute(session->hmacSigningContext,
                (void*)&msg.smb2Header, sizeof(SMB2Header) + bodyLength);
            memcpy(&msg.smb2Header.Signature,
                session->hmacSigningContext->u[0].ctx.hash, 16);
        } else {
            aes_cmac_compute(session->cmacSigningContext,
                (void*)&msg.smb2Header, sizeof(SMB2Header) + bodyLength);
            memcpy(&msg.smb2Header.Signature,
                session->cmacSigningContext->ctx.data, 16);
        }
    }
    
    msg.directTCPHeader.StreamProtocolLength =
        hton32(sizeof(SMB2Header) + bodyLength);

    tcperr =
        TCPIPWriteTCP(connection->ipid, (void*)&msg,
                      4 + sizeof(SMB2Header) + bodyLength, TRUE, FALSE);
    return !(tcperr || toolerror());
}

ReadStatus SendRequestAndGetResponse(DIB *dib, uint16_t command,
                                     uint16_t bodyLength) {
    Session *session = dib->session;
    Connection *connection = session->connection;
    uint64_t messageId;
    bool blockRetry = false;
    ReadStatus status;

retry:
    messageId = connection->nextMessageId;
    msgBodyHeader.StructureSize = requestStructureSizes[command];
    
    // Pad body to at least equal structure size (required by Windows).
    if (bodyLength < msgBodyHeader.StructureSize)
        msg.body[bodyLength++] = 0;
    
    if (SendMessage(session, command, dib->treeId, bodyLength) == false) {
        if (!blockRetry && Reconnect(dib, bodyLength)) {
            blockRetry = true;
            goto retry;
        } else {
            return rsError;
        }
    }

    do {
        status = ReadMessage(connection);
        if (status != rsDone) {
            if (status != rsBadMsg && !blockRetry
                && Reconnect(dib, bodyLength)) {
                blockRetry = true;
                goto retry;
            } else {
                return rsError;
            }
        }
        
        // Check that the message received is a response to the one sent.
        if (!(msg.smb2Header.Flags & SMB2_FLAGS_SERVER_TO_REDIR))
            return rsError;
        if (msg.smb2Header.MessageId != messageId)
            return rsError;
        if (msg.smb2Header.Command != command)
            return rsError;
        
        if (bodySize < (responseStructureSizes[command] & 0xFFFE)
            || msgBodyHeader.StructureSize != responseStructureSizes[command]) {
            blockRetry = true;
            continue;
        }
    
        if (msg.smb2Header.Status == STATUS_SUCCESS) {
            return rsDone;
        } else if ((msg.smb2Header.Status == STATUS_BUFFER_OVERFLOW)
            && (msg.smb2Header.Command == SMB2_READ)) {
            /*
             * STATUS_BUFFER_OVERFLOW may be returned on a named pipe read to
             * indicate that only part of the message would fit in the buffer.
             * This is not a failure, and the data that fits is still returned.
             * See [MS-SMB2] section 3.3.4.4.
             */
            return rsDone;
        } else if (msg.smb2Header.Status == STATUS_MORE_PROCESSING_REQUIRED) {
            return rsMoreProcessingRequired;
        }
        
        blockRetry = true; // because msg has been overwritten
    } while (msg.smb2Header.Status == STATUS_PENDING &&
        (msg.smb2Header.Flags & SMB2_FLAGS_ASYNC_COMMAND));

    // Check for something that looks like an SMB2 ERROR Response
    if (bodySize >= (SMB2_ERROR_RESPONSE_STRUCTURE_SIZE & 0xFFFE)
        && msgBodyHeader.StructureSize == SMB2_ERROR_RESPONSE_STRUCTURE_SIZE) {
        return rsFailed;
    } else {
        return rsError;
    }
}

static bool Reconnect(DIB *dib, uint16_t bodyLength) {
    Connection *connection = dib->session->connection;
    bool result;
    unsigned char *savedBody;
    
    if (GetTick() - connection->reconnectTime
        < MIN_RECONNECT_TIME * 60)
        return false;
    
    connection->reconnectTime = GetTick();

    savedBody = smb_malloc(bodyLength);
    if (savedBody == NULL)
        return false;
    memcpy(savedBody, msg.body, bodyLength);
    
    /*
     * Save info about the file being accessed (if any), so that the fileId
     * can be updated as part of the reconnect process.
     */
    reconnectInfo.dib = dib;
    if (fileIdOffsets[msg.smb2Header.Command] != 0) {
        reconnectInfo.fileId =
            (SMB2_FILEID*)(savedBody + fileIdOffsets[msg.smb2Header.Command]);
    } else {
        reconnectInfo.fileId = NULL;
    }

    result = Connection_Reconnect(connection) == 0;

    memcpy(msg.body, savedBody, bodyLength);
    smb_free(savedBody);

    if (reconnectInfo.fileId != NULL)
        return result;

    return result;
}

void InitSMB(void) {
    fileIdOffsets[SMB2_NEGOTIATE] = 0;
    fileIdOffsets[SMB2_SESSION_SETUP] = 0;
    fileIdOffsets[SMB2_LOGOFF] = 0;
    fileIdOffsets[SMB2_TREE_CONNECT] = 0;
    fileIdOffsets[SMB2_TREE_DISCONNECT] = 0;
    fileIdOffsets[SMB2_CREATE] = 0;
    fileIdOffsets[SMB2_CLOSE] = offsetof(SMB2_CLOSE_Request, FileId);
    fileIdOffsets[SMB2_FLUSH] = offsetof(SMB2_FLUSH_Request, FileId);
    fileIdOffsets[SMB2_READ] = offsetof(SMB2_READ_Request, FileId);
    fileIdOffsets[SMB2_WRITE] = offsetof(SMB2_WRITE_Request, FileId);
    //fileIdOffsets[SMB2_LOCK] = offsetof(SMB2_LOCK_Request, FileId);
    //fileIdOffsets[SMB2_IOCTL] = offsetof(SMB2_IOCTL_Request, FileId);
    fileIdOffsets[SMB2_CANCEL] = 0;
    fileIdOffsets[SMB2_ECHO] = 0;
    fileIdOffsets[SMB2_QUERY_DIRECTORY] = offsetof(SMB2_QUERY_DIRECTORY_Request, FileId);
    //fileIdOffsets[SMB2_CHANGE_NOTIFY] = offsetof(SMB2_CHANGE_NOTIFY_Request, FileId);
    fileIdOffsets[SMB2_QUERY_INFO] = offsetof(SMB2_QUERY_INFO_Request, FileId);
    fileIdOffsets[SMB2_SET_INFO] = offsetof(SMB2_SET_INFO_Request, FileId);
    //fileIdOffsets[SMB2_OPLOCK_BREAK] = offsetof(SMB2_OPLOCK_BREAK_Request, FileId);
}
