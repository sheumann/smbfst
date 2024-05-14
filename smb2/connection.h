#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <types.h>
#include "driver/dib.h"

struct hmac_sha256_context;

typedef struct {
    Word ipid;
    
    uint64_t nextMessageId;
    
    uint16_t dialect;
    
    bool wantSigning; // flag set in Negotiate, but not necessarily in effect yet
    
    Word refCount;
    
    int64_t timeDiff; // difference of IIGS local time from server UTC time

    LongWord serverIP;
    LongWord serverPort;
    
    LongWord reconnectTime;
    LongWord lastActivityTime;
    
    // size of not-yet processed portion of a compound message
    uint32_t remainingCompoundSize;
} Connection;

extern DIB fakeDIB;

void Connection_Retain(Connection *conn);
void Connection_Release(Connection *conn);
Word Connect(Connection *connection);
Word Connection_Reconnect(Connection *connection);

#endif
