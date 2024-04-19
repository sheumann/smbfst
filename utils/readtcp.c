#include <stdint.h>
#include <stdbool.h>
#include <tcpip.h>
#include <misctool.h>
#include <orca.h>

#include "utils/readtcp.h"
#include "defs.h"

/* Time out if no new data is received for this long */
#define READ_TIMEOUT 20 /* seconds */

ReadStatus ReadTCP(Word ipid, uint16_t size, void *buf) {
    static rrBuff rrBuf;
    static Long startTime;
    
    startTime = GetTick();
    do {
        TCPIPPoll();
        if (TCPIPReadTCP(ipid, 0, (Ref)buf, size, &rrBuf) || toolerror()) {
            return rsError;
        }
    
        size -= rrBuf.rrBuffCount;
        buf = (char*)buf + rrBuf.rrBuffCount;
    } while (size != 0 && GetTick() - startTime < READ_TIMEOUT * 60);

    return size == 0 ? rsDone : rsTimedOut;
}
