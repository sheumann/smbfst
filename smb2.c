#include <tcpip.h>
#include <orca.h>

#include <misctool.h>
#include <stdio.h>

#include "defs.h"
#include "connection.h"
#include "endian.h"
#include "smb2proto.h"

static const smb_u128 u128_zero = {0,0};

static struct {
    DirectTCPHeader directTCPHeader;
    SMB2Header smb2header;
    unsigned char body[12345];
} msg;

#define negotiateRequest (*(SMB2_NEGOTIATE_Request*)msg.body)

void SyncMessage(Connection *connection, uint16_t command, uint32_t treeId,
                 uint32_t bodyLength) {
    Word tcperr;

    msg.smb2header.ProtocolId = 0x424D53FE;
    msg.smb2header.StructureSize = 64;
    
    if (connection->Dialect = SMB_202) {
        msg.smb2header.CreditCharge = 0;
    } else {
        UNIMPLEMENTED
    }
    
    if (connection->Dialect <= SMB_21) {
        msg.smb2header.Status = 0;
    } else {
        UNIMPLEMENTED
    }
    
    msg.smb2header.Command = command;
    
    msg.smb2header.CreditRequest = 256; // TODO handle credits
    
    msg.smb2header.Flags = 0;
    msg.smb2header.NextCommand = 0;
    msg.smb2header.MessageId = connection->nextMessageId;
    msg.smb2header.Reserved2 = 0;
    msg.smb2header.TreeId = treeId;
    msg.smb2header.SessionId = connection->sessionId;
    msg.smb2header.Signature = u128_zero;
    
    msg.directTCPHeader.StreamProtocolLength =
        hton32(sizeof(SMB2Header) + bodyLength);

    tcperr =
        TCPIPWriteTCP(connection->ipid, (void*)&msg,
                      4 + sizeof(SMB2Header) + bodyLength, TRUE, FALSE);
    if (tcperr || toolerror()) {
        printf("tcperr=%d, toolerror()=%x\n", tcperr, toolerror());
        /* TODO handle error */
    }

    Long startTime = GetTick();
    do {
        TCPIPPoll();
    } while (GetTick() - startTime < 5*60);
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
    
    SyncMessage(connection, SMB2_NEGOTIATE, 0,
        sizeof(negotiateRequest) + 4*sizeof(negotiateRequest.Dialects[0]));
}