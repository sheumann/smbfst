#ifndef RPC_H
#define RPC_H

#include <stdint.h>
#include <stdbool.h>
#include <types.h>
#include "rpc/rpcpdu.h"

typedef struct {
    Word refNum;
    uint32_t callId;
} RPCConnection;

bool ConnectRPC(RPCConnection *conn, char *name);
void DisconnectRPC(RPCConnection *conn);
uint32_t RPCBind(RPCConnection *conn, const p_syntax_id_t *abstractSyntax);
Handle RPCRequest(RPCConnection *conn, uint16_t opnum,
    void *stubData, uint16_t requestStubSize);

#endif
