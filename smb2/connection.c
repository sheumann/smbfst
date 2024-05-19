#include "defs.h"

#include <tcpip.h>
#include <gsos.h>
#include <misctool.h>
#include <time.h>
#include <orca.h>
#include <stdlib.h>
#include "smb2/smb2.h"
#include "smb2/connection.h"
#include "smb2/session.h"
#include "utils/alloc.h"
#include "driver/driver.h"
#include "helpers/datetime.h"

// Timeout for TCP connection establishment
#define TIMEOUT 15 /* seconds */

// Max allowed offset between GS local time and UTC (in FILETIME units)
#define MAX_TZ_OFFSET (18LL * 60 * 60 * 10000000)

DIB fakeDIB = {0};

void Connection_Retain(Connection *conn) {
    ++conn->refCount;
}

void Connection_Release(Connection *conn) {
    if (--conn->refCount == 0) {
        TCPIPAbortTCP(conn->ipid);
        TCPIPLogout(conn->ipid);
        smb_free(conn);
    }
}

Word Connect(Connection *connection) {
    static ReadStatus result;
    static Word tcpError;
    static srBuff status;
    static Long startTime;
    static Session dummySession = {0};
    static uint64_t timeDiff;
    unsigned i;

    connection->ipid = TCPIPLogin(userid(), connection->serverIP,
        connection->serverPort, 0, 64);
    if (toolerror()) {
        return networkError;
    }

    tcpError = TCPIPOpenTCP(connection->ipid);
    if (tcpError || toolerror()) {
        TCPIPLogout(connection->ipid);
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
        return networkError;
    }

    connection->lastActivityTime = GetTick();

    // assume lowest version until we have negotiated
    connection->dialect = SMB_202;

    connection->nextMessageId = 0;
    connection->remainingCompoundSize = 0;
    connection->requestedCredits = false;

    negotiateRequest.SecurityMode = 0;
    negotiateRequest.Reserved = 0;
    negotiateRequest.Capabilities = 0;
    
    // TODO generate real GUID
    negotiateRequest.ClientGuid = (smb_u128){0xa248283946289746,0xac65879365873456};
    
    negotiateRequest.ClientStartTime = 0;

    negotiateRequest.DialectCount = 4;
    negotiateRequest.Dialects[0] = SMB_202;
    negotiateRequest.Dialects[1] = SMB_21;
    negotiateRequest.Dialects[2] = SMB_30;
    negotiateRequest.Dialects[3] = SMB_302;
    
    dummySession.connection = connection;
    fakeDIB.session = &dummySession;
    result = SendRequestAndGetResponse(&fakeDIB, SMB2_NEGOTIATE,
        sizeof(negotiateRequest) + 4*sizeof(negotiateRequest.Dialects[0]));
    if (result != rsDone) {
        TCPIPAbortTCP(connection->ipid);
        TCPIPLogout(connection->ipid);
        return networkError;
    }

    /*
     * Compute difference between IIGS local time and server UTC time.
     * 
     * We add in a second because times get truncated to the second both
     * when getting the local time here and in some subsequent operations,
     * so we effectively cannot get sub-second accuracy, and having the
     * time difference be slightly too large may give better results after
     * subsequent truncations.
     */
    timeDiff =
        TIME_TO_FILETIME(time(NULL) + 1) - negotiateResponse.SystemTime;

    /*
     * If GS local time and server UTC time differ by more than 18 hours,
     * one or the other is wrong.  Guess that the GS is wrong (e.g. due to
     * a dead battery), and just report times using server UTC.
     */
    if (llabs(timeDiff) > MAX_TZ_OFFSET)
        timeDiff = 0;

    /*
     * If multiple connections are made to a macOS server, it may report the
     * same time for subsequent connections as it did for the first one, even
     * though that is no longer the current time.  If we encounter this
     * situation, we copy the time difference from the earlier connection.
     */
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].extendedDIBPtr != NULL
            && dibs[i].session->connection->serverIP == connection->serverIP
            && dibs[i].session->connection->connectTime
                == negotiateResponse.SystemTime) {
            timeDiff = dibs[i].session->connection->timeDiff;
            break;
        }
    }

    connection->connectTime = negotiateResponse.SystemTime;
    connection->timeDiff = timeDiff;

    connection->wantSigning =
        negotiateResponse.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED;
        
    if (negotiateResponse.DialectRevision != SMB_202 &&
        negotiateResponse.DialectRevision != SMB_21 &&
        negotiateResponse.DialectRevision != SMB_30 &&
        negotiateResponse.DialectRevision != SMB_302) {
        TCPIPAbortTCP(connection->ipid);
        TCPIPLogout(connection->ipid);
        return networkError;
    }
    connection->dialect = negotiateResponse.DialectRevision;
    
    if (negotiateResponse.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED) {
        connection->wantSigning = true;
    }
    
    // Security buffer is currently ignored
    
    return 0;
}

Word Connection_Reconnect(Connection *connection) {
    Word result, result2;
    Word oldIpid;
    unsigned i;
    
    oldIpid = connection->ipid;
    TCPIPAbortTCP(oldIpid);
    result = Connect(connection);
    
    if (result != 0) {
        connection->ipid = oldIpid;
    } else {
        TCPIPLogout(oldIpid);
        
        for (i = 0; i < ARRAY_LENGTH(sessions); i++) {
            if (sessions[i].connection == connection) {
                result2 = Session_Reconnect(&sessions[i]);
                if (&sessions[i] == reconnectInfo.dib->session)
                    result = result2;
            }
        }
    }
    
    return result;
}
