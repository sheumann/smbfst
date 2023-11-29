#include <stdbool.h>
#include <tcpip.h>
#include <orca.h>

#include <misctool.h>
#include <stdio.h>

#include "defs.h"
#include "connection.h"
#include "endian.h"
#include "smb2proto.h"
#include "readtcp.h"

static const smb_u128 u128_zero = {0,0};

static struct {
    DirectTCPHeader directTCPHeader;
    SMB2Header smb2Header;
    unsigned char body[32768];
} msg;

#define negotiateRequest (*(SMB2_NEGOTIATE_Request*)msg.body)


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
}

bool SendMessage(Connection *connection, uint16_t command, uint32_t treeId,
                 uint16_t bodyLength) {
    Word tcperr;

    msg.smb2Header.ProtocolId = 0x424D53FE;
    msg.smb2Header.StructureSize = 64;
    
    if (connection->Dialect = SMB_202) {
        msg.smb2Header.CreditCharge = 0;
    } else {
        UNIMPLEMENTED
    }
    
    if (connection->Dialect <= SMB_21) {
        msg.smb2Header.Status = 0;
    } else {
        UNIMPLEMENTED
    }
    
    msg.smb2Header.Command = command;
    
    msg.smb2Header.CreditRequest = 256; // TODO handle credits
    
    msg.smb2Header.Flags = 0;
    msg.smb2Header.NextCommand = 0;
    msg.smb2Header.MessageId = connection->nextMessageId;
    msg.smb2Header.Reserved2 = 0;
    msg.smb2Header.TreeId = treeId;
    msg.smb2Header.SessionId = connection->sessionId;
    msg.smb2Header.Signature = u128_zero;
    
    msg.directTCPHeader.StreamProtocolLength =
        hton32(sizeof(SMB2Header) + bodyLength);

    tcperr =
        TCPIPWriteTCP(connection->ipid, (void*)&msg,
                      4 + sizeof(SMB2Header) + bodyLength, TRUE, FALSE);
    return !(tcperr || toolerror());
}

ReadStatus SendMessageAndGetResponse(Connection *connection, uint16_t command,
                                     uint32_t treeId, uint16_t bodyLength) {
    uint64_t messageId = connection->nextMessageId;
    if (SendMessage(connection, command, treeId, bodyLength) == false)
        return rsError;

    if (ReadMessage(connection) != rsDone)
        return rsError;
    
    // Check that the message received is a response to the one sent.
    if (!(msg.smb2Header.Flags & SMB2_FLAGS_SERVER_TO_REDIR))
        return rsError;
    if (msg.smb2Header.MessageId != messageId)
        return rsError;

    return rsDone;
}

void Negotiate(Connection *connection) {
    negotiateRequest.StructureSize = 36;
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
    
    SendMessageAndGetResponse(connection, SMB2_NEGOTIATE, 0,
        sizeof(negotiateRequest) + 4*sizeof(negotiateRequest.Dialects[0]));
}