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

// Position for next message to be enqueued
SMB2Message *nextMsg = (SMB2Message *)&msg.smb2Header;

// Pointer to last message enqueued, if any
static SMB2Message *lastMsg = NULL;

// Total length of data enqueued to send
static uint16_t sendLength = 0;

// Maximum number of messages that we allow to be compounded
#define MAX_COMPOUND_SIZE 3

// Message number to use for next message enqueued
static uint16_t nextMessageNum = 0;

// Message IDs and commands for last set of messages enqueued/sent
static uint64_t msgIDs[MAX_COMPOUND_SIZE];
static uint16_t msgCommands[MAX_COMPOUND_SIZE];

// Block from retrying a send (because message has been overwritten)?
bool blockRetry = false;

#define MIN_RECONNECT_TIME 5 /* seconds */

static bool Reconnect(DIB *dib);

static const smb_u128 u128_zero = {0,0};

// File Id indicating the file created previously within a compounded request
const SMB2_FILEID fileIDFromPrevious =
    {0xffffffffffffffff, 0xffffffffffffffff};

MsgRec msg;

uint16_t bodySize;   // size of last message received

ReconnectInfo reconnectInfo;

/*
 * Read an SMB2 protocol message from the connection.
 * On success, the message is left in msg.smb2Header and msg.body.
 */
static ReadStatus ReadMessage(Connection *connection) {
    ReadStatus result;
    uint32_t msgSize;
    
    if (connection->remainingCompoundSize == 0) {
        result =
            ReadTCP(connection, 4 + sizeof(SMB2Header), &msg.directTCPHeader);
        if (result != rsDone)
            return result;
        
        connection->remainingCompoundSize =
            ntoh32(msg.directTCPHeader.StreamProtocolLength);
    } else {
        result = ReadTCP(connection, sizeof(SMB2Header), &msg.smb2Header);
        if (result != rsDone)
            return result;
    }

    blockRetry = true;

    if (msg.smb2Header.NextCommand != 0) {
        if (msg.smb2Header.NextCommand >= connection->remainingCompoundSize)
            return rsBadMsg;

        connection->remainingCompoundSize -= msg.smb2Header.NextCommand;
        msgSize = msg.smb2Header.NextCommand;
        
        if (connection->remainingCompoundSize != 0
            && connection->remainingCompoundSize < sizeof(SMB2Header)) {
            connection->remainingCompoundSize = 0;
            return rsBadMsg;
        }
    } else {
        msgSize = connection->remainingCompoundSize;
        connection->remainingCompoundSize = 0;
    }
    
    // Check that it looks like an SMB2/3 message
    
    if (msgSize < sizeof(SMB2Header))
        return rsBadMsg;
    if (msg.smb2Header.ProtocolId != 0x424D53FE)
        return rsBadMsg;
    if (msg.smb2Header.StructureSize != 64)
        return rsBadMsg;

    if (msgSize > sizeof(SMB2Header) + sizeof(msg.body))
        return rsBadMsg;
    
    result = ReadTCP(connection, msgSize - sizeof(SMB2Header), &msg.body);
    if (result != rsDone)
        return rsBadMsg;
    
    bodySize = msgSize - sizeof(SMB2Header);
    
    return rsDone;
}

/*
 * Check if there is space available in the buffer for another message with
 * the specified body length.  If there is not, any already-buffered messages
 * are cleared.
 */
bool SpaceAvailable(uint16_t bodyLength) {
    if (msg.body + sizeof(msg.body) - (unsigned char *)nextMsg
        < sizeof(SMB2Header) + bodyLength) {
        ResetSendStatus();
        return false;
    }
    return true;
}

/*
 * Enqueue a SMB2 request message to be sent later.
 * If multiple messages are enqueued, they are compounded as related requests.
 * Returns a message number that can be used to get the response.
 */
unsigned EnqueueRequest(DIB *dib, uint16_t command, uint16_t bodyLength) {
    Session *session = dib->session;
    Connection *connection = session->connection;
    SMB2Header *header = &nextMsg->Header;

    if (lastMsg != NULL) {
        // Zero out padding
        *(uint64_t*)((char*)&msg.smb2Header + sendLength) = 0;

        header->Flags = SMB2_FLAGS_RELATED_OPERATIONS;
        lastMsg->Header.NextCommand = (char*)nextMsg - (char*)lastMsg;
    } else {
        header->Flags = 0;
    }
    
    header->ProtocolId = 0x424D53FE;
    header->StructureSize = 64;

    if (connection->dialect == SMB_202) {
        header->CreditCharge = 0;
    } else {
        // Our messages are always < 64K, so CreditCharge is just 1.
        header->CreditCharge = 1;
    }
    
    // Note: In SMB 3.x, this is actually ChannelSequence + Reserved.
    header->Status = 0;
    
    header->Command = command;
    
    if (command == SMB2_TREE_CONNECT && !connection->requestedCredits) {
        header->CreditRequest = MAX_COMPOUND_SIZE;
        connection->requestedCredits = true;
    } else {
        header->CreditRequest = 1;
    }

    header->NextCommand = 0;
    header->MessageId = connection->nextMessageId++;
    header->Reserved2 = 0;
    header->TreeId = dib->treeId;
    header->SessionId = session->sessionId;
    header->Signature = u128_zero;
    
    ((SMB2_Common_Header*)nextMsg->Body)->StructureSize =
        requestStructureSizes[command];

    sendLength = ((sendLength + 7) & 0xfff8) + sizeof(SMB2Header) + bodyLength;
    lastMsg = nextMsg;
    
    nextMsg = (void*)((char*)&msg.smb2Header + ((sendLength + 7) & 0xfff8));
    
    msgIDs[nextMessageNum] = header->MessageId;
    msgCommands[nextMessageNum] = command;
    return nextMessageNum++;
}

/*
 * Send all currently-enqueued messages.
 */
bool SendMessages(DIB *dib) {
    Session *session = dib->session;
    Connection *connection = session->connection;
    SMB2Message *message;
    uint16_t msgLen;
    uint16_t remainingLen;
    Word tcperr;

    if (session->signingRequired) {
        message = (SMB2Message *)&msg.smb2Header;
        remainingLen = sendLength;
        
        do {
            if (message->Header.NextCommand != 0) {
                msgLen = message->Header.NextCommand;
            } else {
                msgLen = remainingLen;
            }

            message->Header.Flags |= SMB2_FLAGS_SIGNED;
            
            if (connection->dialect <= SMB_21) {
                hmac_sha256_compute(session->hmacSigningContext,
                    (void*)message, msgLen);
                memcpy(&message->Header.Signature,
                    session->hmacSigningContext->u[0].ctx.hash, 16);
            } else {
                aes_cmac_compute(session->cmacSigningContext,
                    (void*)message, msgLen);
                memcpy(&message->Header.Signature,
                    session->cmacSigningContext->ctx.data, 16);
            }
            
            message = (SMB2Message *)((char*)message + msgLen);
            remainingLen -= msgLen;
        } while (remainingLen != 0);
    }
    
    msg.directTCPHeader.StreamProtocolLength =
        hton32(sendLength);

    blockRetry = false;

    tcperr = TCPIPWriteTCP(connection->ipid, (void*)&msg, 4 + sendLength,
        TRUE, FALSE);
    return !(tcperr || toolerror());
}

/*
 * Clear the send buffer, discarding any enqueued messages.
 */
void ResetSendStatus(void) {
    nextMsg = (SMB2Message *)&msg.smb2Header;
    lastMsg = NULL;
    sendLength = 0;
    nextMessageNum = 0;
}

/*
 * Get a response to a message from the last batch sent.
 * messageNum is the number returned from EnqueueRequest for it.
 * Responses must be received in the order that the messages were enqueued.
 */
ReadStatus GetResponse(DIB *dib, uint16_t messageNum) {
    ReadStatus status;
    uint16_t command = msgCommands[messageNum];

    do {
retry:
        status = ReadMessage(dib->session->connection);
        if (status != rsDone) {
            if (status != rsBadMsg && !blockRetry
                && Reconnect(dib)) {
                SendMessages(dib);
                blockRetry = true;
                goto retry;
            } else {
                ResetSendStatus();
                return rsError;
            }
        }
        
        ResetSendStatus();
        
        // Check that the message received is a response to the one sent.
        if (!(msg.smb2Header.Flags & SMB2_FLAGS_SERVER_TO_REDIR))
            return rsError;
        if (msg.smb2Header.MessageId != msgIDs[messageNum])
            return rsError;
        if (msg.smb2Header.Command != command)
            return rsError;
        
        if (bodySize < (responseStructureSizes[command] & 0xFFFE)
            || msgBodyHeader.StructureSize != responseStructureSizes[command])
            continue;
    
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

/*
 * Send a single message and get a response for it.
 */
ReadStatus SendRequestAndGetResponse(DIB *dib, uint16_t command,
                                     uint16_t bodyLength) {
    uint16_t messageNum;
    
    // Pad body to at least equal structure size (required by Windows).
    if (bodyLength < requestStructureSizes[command])
        msg.body[bodyLength++] = 0;
    
    messageNum = EnqueueRequest(dib, command, bodyLength);

    SendMessages(dib);
    return GetResponse(dib, messageNum);
}

/*
 * Reconnect after the connection has been dropped.
 * This tries to reconnect the connection and all its sessions, tree connects,
 * and open files.  The previously sent group of messages are re-enqueued.
 */
static bool Reconnect(DIB *dib) {
    Connection *connection = dib->session->connection;
    bool result;
    unsigned char *savedMsg;
    uint16_t savedLength;
    uint16_t msgLen;
    
    if (GetTick() - connection->reconnectTime
        < MIN_RECONNECT_TIME * 60)
        return false;
    
    connection->reconnectTime = GetTick();

    savedLength = sendLength;
    savedMsg = smb_malloc(savedLength);
    if (savedMsg == NULL)
        return false;
    memcpy(savedMsg, &msg.smb2Header, savedLength);
    
    /*
     * Save info about the file being accessed (if any), so that the fileId
     * can be updated as part of the reconnect process.
     * NOTE: This currently only works for the first message in a compound set.
     */
    reconnectInfo.dib = dib;
    if (fileIdOffsets[msg.smb2Header.Command] != 0) {
        reconnectInfo.fileId =
            (SMB2_FILEID*)(savedMsg + sizeof(SMB2Header)
            + fileIdOffsets[msg.smb2Header.Command]);
    } else {
        reconnectInfo.fileId = NULL;
    }

    ResetSendStatus();
    result = Connection_Reconnect(connection) == 0;

    memcpy(&msg.smb2Header, savedMsg, savedLength);
    smb_free(savedMsg);
    
    // Re-enqueue messages to rebuild their headers as necessary
    do {
        if (nextMsg->Header.NextCommand != 0) {
            msgLen = nextMsg->Header.NextCommand;
        } else {
            msgLen = savedLength;
        }
        EnqueueRequest(dib, nextMsg->Header.Command,
            msgLen - sizeof(SMB2Header));
        savedLength -= msgLen;
    } while (savedLength != 0);

    if (reconnectInfo.fileId != NULL)
        return false;

    return result;
}

/*
 * Initialize data for SMB at start-up.
 */
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
