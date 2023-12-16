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
    
    uint64_t sessionId; // TODO separate session structure?
    
    bool signingRequired;
    struct hmac_sha256_context *signingContext;
} Connection;

#endif
