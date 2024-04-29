#include <stdint.h>
#include <stdbool.h>
#include <tcpip.h>
#include <misctool.h>
#include <orca.h>

#include "smb2/connection.h"
#include "utils/readtcp.h"
#include "defs.h"

/* Time out if no new data is received for this long */
#define READ_TIMEOUT (20*60) /* ticks */

/* Read timeout when connection has been inactive */
#define INACTIVE_READ_TIMEOUT (2*60) /* ticks */

/*
 * Period after which the connection is considered inactive.  We apply a
 * shorter timeout in this case in order to avoid long hangs that can be
 * caused by Windows behavior.  Specifically, Windows eventually drops
 * SMB connections after a period of inactivity, but with the default
 * Windows firewall configuration, it will just silently ignore any 
 * traffic from the GS after that.  Windows will never send a TCP FIN or
 * RST packet in this situation, so the GS does not know the connection
 * has been dropped.  It will therefore wait for the timeout period
 * before reporting a failure.  By applying a shorter timeout, we can
 * report the failure sooner and allow a reconnection attempt to begin.
 */
#define INACTIVITY_PERIOD (2*60*60) /* ticks */

ReadStatus ReadTCP(Connection *connection, uint16_t size, void *buf) {
    static rrBuff rrBuf;
    static Long startTime;
    static uint16_t timeout;
    
    startTime = GetTick();
    if (startTime - connection->lastActivityTime > INACTIVITY_PERIOD) {
        timeout = INACTIVE_READ_TIMEOUT;
    } else {
        timeout = READ_TIMEOUT;
    }
    connection->lastActivityTime = startTime;
    
    do {
        TCPIPPoll();
        if (TCPIPReadTCP(connection->ipid, 0, (Ref)buf, size, &rrBuf)
            || toolerror()) {
            return rsError;
        }
    
        size -= (uint16_t)rrBuf.rrBuffCount;
        if (size == 0)
            return rsDone;

        if (rrBuf.rrBuffCount != 0) {
            buf = (char*)buf + rrBuf.rrBuffCount;
            timeout = READ_TIMEOUT;
        }
    } while (GetTick() - startTime < timeout);

    if (size == 0) {
        return rsDone;
    } else {
        TCPIPAbortTCP(connection->ipid);
        return rsTimedOut;
    }
}
