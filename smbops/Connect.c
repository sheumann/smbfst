#include "defs.h"

#include <gsos.h>
#include <tcpip.h>
#include <orca.h>
#include <misctool.h>
#include <string.h>
#include "fstspecific.h"
#include "smb2.h"
#include "alloc.h"

// Timeout for TCP connection establishment
#define TIMEOUT 15 /* seconds */

Word SMB_Connect(SMBConnectRec *pblock, void *gsosdp, Word pcount) {
    static ReadStatus result;
    static Word tcpError;
    static srBuff status;
    static Long startTime;
    static Session dummySession = {0};

    if (pblock->pCount != 7)
        return invalidPcount;
    
    Connection *connection = smb_malloc(sizeof(Connection));
    if (!connection)
        return outOfMem;
    
    memset(connection, 0, sizeof(Connection));
    
    connection->ipid = TCPIPLogin(userid(), pblock->serverIP,
        pblock->serverPort ? pblock->serverPort : SMB_PORT, 0, 64);
    if (toolerror()) {
        smb_free(connection);
        return networkError;
    }

    tcpError = TCPIPOpenTCP(connection->ipid);
    if (tcpError || toolerror()) {
        TCPIPLogout(connection->ipid);
        smb_free(connection);
        return networkError;
    }
    
    startTime = GetTick();
    do {
        TCPIPPoll();
        TCPIPStatusTCP(connection->ipid, &status);
    } while (
        status.srState != TCPSESTABLISHED && status.srState != TCPSCLOSED
        && GetTick() - startTime < TIMEOUT * 60);
    
    if (status.srState != TCPSESTABLISHED) {
        TCPIPAbortTCP(connection->ipid);
        TCPIPLogout(connection->ipid);
        smb_free(connection);
        return networkError;
    }

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
    
    dummySession.connection = connection;
    result = SendRequestAndGetResponse(&dummySession, SMB2_NEGOTIATE, 0,
        sizeof(negotiateRequest) + 4*sizeof(negotiateRequest.Dialects[0]));
    if (result != rsDone) {
        TCPIPAbortTCP(connection->ipid);
        TCPIPLogout(connection->ipid);
        smb_free(connection);
        return networkError;
    }
    
    connection->wantSigning =
        negotiateResponse.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED;
        
    if (negotiateResponse.DialectRevision != SMB_202) {
        // TODO handle other dialects
        TCPIPAbortTCP(connection->ipid);
        TCPIPLogout(connection->ipid);
        smb_free(connection);
        return networkError;
    }
    connection->dialect = negotiateResponse.DialectRevision;
    
    if (negotiateResponse.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED) {
        connection->wantSigning = true;
    }
    
    // TODO compute time difference based on negotiateResponse.SystemTime
    
    // Security buffer is currently ignored
    
    connection->refCount = 1;
    pblock->connectionID = (LongWord)connection;
    return 0;
}
