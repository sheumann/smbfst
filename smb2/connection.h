/*
 * Copyright (c) 2024 Stephen Heumann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
    int64_t connectTime; // UTC time the server reported when it connected

    LongWord serverIP;
    LongWord serverPort;
    
    LongWord reconnectTime;
    LongWord lastActivityTime;
    
    // size of not-yet processed portion of a compound message
    uint32_t remainingCompoundSize;
    
    bool requestedCredits;
} Connection;

extern DIB fakeDIB;

void Connection_Retain(Connection *conn);
void Connection_Release(Connection *conn);
Word Connect(Connection *connection);
Word Connection_Reconnect(Connection *connection);

#endif
