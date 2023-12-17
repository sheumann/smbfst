#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <stdint.h>
#include <stdbool.h>
#include <types.h>

struct hmac_sha256_context;

typedef struct {
    Word ipid;
    
    uint64_t nextMessageId;
    
    uint16_t dialect;
    
    bool wantSigning; // flag set in Negotiate, but not necessarily in effect yet
    
    Word refCount;
} Connection;

void Connection_Retain(Connection *conn);
void Connection_Release(Connection *conn);

#endif
