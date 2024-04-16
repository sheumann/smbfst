#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <types.h>
#include "connection.h"

struct hmac_sha256_context;

typedef struct {
    Connection *connection;

    uint64_t sessionId; // TODO separate session structure?
    
    bool signingRequired;
    union {
        struct hmac_sha256_context *hmacSigningContext;
        struct aes_cmac_context *cmacSigningContext;
    };
    
    Word refCount;
} Session;

void Session_Retain(Session *sess);
void Session_Release(Session *sess);

#endif
