#include <tcpip.h>
#include <orca.h>

#include <misctool.h>
#include <stdio.h>

#include "defs.h"
#include "connection.h"
#include "endian.h"
#include "smb2proto.h"

static SMB2Header header;

static const smb_u128 u128_zero = {0,0};

void SyncMessage(Connection *connection, uint16_t command, uint32_t treeId,
                 uint32_t length1, const void *part1,
                 uint32_t length2, const void *part2) {
    Word tcperr;

    header.ProtocolId = 0x424D53FE;
    header.StructureSize = 64;
    
    if (connection->Dialect = SMB_202) {
        header.CreditCharge = 0;
    } else {
        UNIMPLEMENTED
    }
    
    if (connection->Dialect <= SMB_21) {
        header.Status = 0;
    } else {
        UNIMPLEMENTED
    }
    
    header.Command = command;
    
    header.CreditRequest = 256; // TODO handle credits
    
    header.Flags = 0;
    header.NextCommand = 0;
    header.MessageId = connection->nextMessageId;
    header.Reserved2 = 0;
    header.TreeId = treeId;
    header.SessionId = connection->sessionId;
    header.Signature = u128_zero;
    
    header.StreamProtocolLength =
        hton32(sizeof(SMB2Header) - 4 + length1 + length2);

    tcperr =
        TCPIPWriteTCP(connection->ipid, (void*)&header, sizeof(header), FALSE, FALSE);
    if (tcperr || toolerror()) {
        printf("tcperr=%d, toolerror()=%x\n", tcperr, toolerror());
        /* TODO handle error */
    }

    tcperr =
        TCPIPWriteTCP(connection->ipid, (void*)part1, length1, length2 != 0, FALSE);
    if (tcperr || toolerror())
        /* TODO handle error */ ;

    if (length2 != 0) {
        tcperr =
            TCPIPWriteTCP(connection->ipid, (void*)part2, length2, TRUE, FALSE);
        if (tcperr || toolerror())
            /* TODO handle error */ ;
    }
    
    Long startTime = GetTick();
    do {
        TCPIPPoll();
    } while (GetTick() - startTime < 5*60);
}

void Negotiate(Connection *connection) {
    static SMB2_NEGOTIATE_Request_Header header;
    static const uint16_t Dialects[4] = {SMB_202};
    
    header.StructureSize = 36;
    header.DialectCount = 1;
    header.SecurityMode = 0;
    header.Reserved = 0;
    header.Capabilities = 0;
    
    // TODO generate real GUID
    header.ClientGuid = (smb_u128){0xa248283946289746,0xac65879365873456};
    
    header.ClientStartTime = 0;
    
    SyncMessage(connection, SMB2_NEGOTIATE, 0, sizeof(header), &header,
        sizeof(Dialects), Dialects);
}