#ifndef __SESSION_H__
#define __SESSION_H__

#include <stdint.h>
#include <stdbool.h>
#include <types.h>
#include "connection.h"

struct hmac_sha256_context;

typedef struct {
    Connection *connection;

    uint64_t sessionId; // TODO separate session structure?
    
    bool signingRequired;
    struct hmac_sha256_context *signingContext;
    
    Word refCount;
} Session;

void Session_Retain(Session *sess);
void Session_Release(Session *sess);

#endif
