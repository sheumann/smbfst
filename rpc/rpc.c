#define USE_BLANK_SEG
#include "defs.h"
#include <memory.h>
#include <stdbool.h>
#include <string.h>
#include <gsos.h>
#include <orca.h>
#include "rpc/rpc.h"
#include "utils/guidutils.h"

// UUID and version for NDR with MS extensions (see C706 and [MS-RPCE])
#define NDR_SYNTAX {.if_uuid = GUID(8a885d04,1ceb,11c9,9fe8,08002b104860), 2}

static IORecGS ioRec = {
    .pCount = 4
};

/*
 * We should be able to use MustRecvFragSize bytes (i.e. 1432), but Samba
 * seems to want at least 2048, so we go with that.
 */
char ioBuf[2048];

bool ConnectRPC(RPCConnection *conn, char *name) {
    static GSString32 gsName;
    static OpenRecGS openRec = {
        .pCount = 3,
        .pathname = (void*)&gsName,
        .requestAccess = readWriteEnable
    };
    
    if (strlen(name) > sizeof(gsName.text))
        return false;
    strcpy(gsName.text, name);
    gsName.length = strlen(name);

    OpenGS(&openRec);
    if (toolerror())
        return false;
    
    conn->refNum = openRec.refNum;
    conn->callId = 1;

    return true;
}

void DisconnectRPC(RPCConnection *conn) {
    static RefNumRecGS closeRec = {
        .pCount = 1
    };

    closeRec.refNum = conn->refNum;
    CloseGS(&closeRec);
}

bool SendRPCData(RPCConnection *conn, void *buffer, uint16_t size) {
    ioRec.refNum = conn->refNum;
    ioRec.dataBuffer = buffer;
    ioRec.requestCount = size;
    WriteGS(&ioRec);
    if (toolerror() || ioRec.transferCount != size)
        return false;
    
    return true;
}

uint32_t ReceiveRPCMessage(RPCConnection *conn, void *buffer, uint32_t bufSize)
{
    if (bufSize < sizeof(rpc_common_header_t))
        return 0;

    ioRec.refNum = conn->refNum;
    ioRec.dataBuffer = buffer;
    ioRec.requestCount = sizeof(rpc_common_header_t);
    ReadGS(&ioRec);
    if (toolerror())
        return 0;
    if (ioRec.transferCount != ioRec.requestCount)
        return 0;
    
    #define header (*(rpc_common_header_t*)buffer)
    if (header.rpc_vers != RPC_CO_MAJOR_VERSION)
        return 0;
    if (header.frag_length < sizeof(rpc_common_header_t))
        return 0;
    if (header.frag_length > bufSize)
        return 0;
    
    ioRec.dataBuffer = (char*)buffer + sizeof(rpc_common_header_t);
    ioRec.requestCount = header.frag_length - sizeof(rpc_common_header_t);
    ReadGS(&ioRec);
    if (toolerror())
        return 0;
    if (ioRec.transferCount != ioRec.requestCount)
        return 0;
    
    return header.frag_length;
    #undef header
}

uint32_t RPCBind(RPCConnection *conn, const p_syntax_id_t *abstractSyntax) {
    uint32_t callId;
    uint32_t msgSize;

    static rpcconn_bind_hdr_t bindMsg = {
        .hdr.rpc_vers = RPC_CO_MAJOR_VERSION,
        .hdr.rpc_vers_minor = 0,
        .hdr.PTYPE = PTYPE_bind,
        .hdr.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG,
        .hdr.packed_drep[0] = DREP_LITTLE_ENDIAN | DREP_ASCII,
        .hdr.packed_drep[1] = DREP_IEEE,
        .hdr.packed_drep[2] = 0,
        .hdr.packed_drep[3] = 0,
        .hdr.frag_length = sizeof(bindMsg),
        .hdr.auth_length = 0,
        .hdr.call_id = 0,           // set dynamically
        .max_xmit_frag = 0xFFFF,
        .max_recv_frag = 0x7FFF,    // set dynamically
        .assoc_group_id = 0,
        .p_context_elem.n_context_elem = 1,
        .p_context_elem.reserved = 0,
        .p_context_elem.reserved2 = 0,
        .p_context_elem.p_cont_elem_1.p_cont_id = 0,
        .p_context_elem.p_cont_elem_1.n_transfer_syn = 1,
        .p_context_elem.p_cont_elem_1.reserved = 0,
        .p_context_elem.p_cont_elem_1.abstract_syntax = {0}, // set dynamically
        .p_context_elem.p_cont_elem_1.transfer_syntax_1 = NDR_SYNTAX,
    };

    callId = conn->callId++;
    bindMsg.hdr.call_id = callId;
    bindMsg.p_context_elem.p_cont_elem_1.abstract_syntax = *abstractSyntax;

    // ensure messages from server will fit in our buffer
    bindMsg.max_recv_frag = sizeof(ioBuf);

    if (!SendRPCData(conn, &bindMsg, sizeof(bindMsg)))
        return 0;
    
    msgSize = ReceiveRPCMessage(conn, ioBuf, sizeof(ioBuf));
    
    if (msgSize < sizeof(rpcconn_bind_ack_hdr_t))
        return 0;
    
#define replyHeader (*(rpc_common_header_t*)ioBuf)
    if (replyHeader.rpc_vers != 5 || replyHeader.rpc_vers_minor != 0)
        return 0;
    if (replyHeader.PTYPE != PTYPE_bind_ack)
        return 0;
    if (replyHeader.packed_drep[0] != DREP_LITTLE_ENDIAN | DREP_ASCII)
        return 0;
    if (replyHeader.call_id != callId)
        return 0;
    if (replyHeader.frag_length != msgSize)
        return 0;

#define reply (*(rpcconn_bind_ack_hdr_t*)ioBuf)
    if (reply.max_xmit_frag > sizeof(ioBuf))
        return 0;
    if (reply.max_recv_frag < MustRecvFragSize)
        return 0;
    return reply.assoc_group_id;
    
#undef reply
#undef replyHeader
}

/*
 * Send an RPC request and get a response.
 *
 * This does not fragment the request, so it must fit within the fragment
 * size limits (potentially as low as MustRecvFragSize, including header).
 *
 * If there is an error, this returns NULL.  Otherwise, it returns a locked
 * handle containing the stub data from the responses (reassembled from
 * fragmented packets, if necessary).  It is the caller's responsibility to
 * dispose of the handle when done with it.
 */
Handle RPCRequest(RPCConnection *conn, uint16_t opnum,
    void *stubData, uint16_t requestStubSize) {
    uint32_t callId;
    uint32_t msgSize;
    Handle dataHandle;
    uint32_t dataSize, newDataSize;
    
    static rpcconn_request_hdr_t requestHeader = {
        .hdr.rpc_vers = RPC_CO_MAJOR_VERSION,
        .hdr.rpc_vers_minor = 0,
        .hdr.PTYPE = PTYPE_request,
        .hdr.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG,
        .hdr.packed_drep[0] = DREP_LITTLE_ENDIAN | DREP_ASCII,
        .hdr.packed_drep[1] = DREP_IEEE,
        .hdr.packed_drep[2] = 0,
        .hdr.packed_drep[3] = 0,
        .hdr.frag_length = 0,       // set dynamically
        .hdr.auth_length = 0,
        .hdr.call_id = 0,           // set dynamically
        .alloc_hint = 0,
        .p_cont_id = 0,
        .opnum = 0,                 // set dynamically
    };

    callId = conn->callId++;
    requestHeader.hdr.call_id = callId;
    requestHeader.hdr.frag_length = sizeof(requestHeader) + requestStubSize;
    requestHeader.opnum = opnum;
    
    if (!SendRPCData(conn, &requestHeader, sizeof(requestHeader)))
        return NULL;
    if (!SendRPCData(conn, stubData, requestStubSize))
        return NULL;
        
    dataSize = 0;
    dataHandle = NewHandle(0, userid(), attrNoSpec, 0);

    do {
        msgSize = ReceiveRPCMessage(conn, ioBuf, sizeof(ioBuf));
    
        if (msgSize < sizeof(rpcconn_response_hdr_t))
            goto error;

#define replyHeader (*(rpc_common_header_t*)ioBuf)
        if (replyHeader.rpc_vers != 5 || replyHeader.rpc_vers_minor != 0)
            goto error;
        if (replyHeader.PTYPE != PTYPE_response)
            goto error;
        if (replyHeader.packed_drep[0] != DREP_LITTLE_ENDIAN | DREP_ASCII)
            goto error;
        if (replyHeader.call_id != callId)
            goto error;
        if (replyHeader.frag_length != msgSize)
            goto error;
        if (replyHeader.auth_length
            > replyHeader.frag_length - sizeof(rpcconn_response_hdr_t))
            goto error;

#define reply (*(rpcconn_response_hdr_t*)ioBuf)    
        newDataSize = replyHeader.frag_length - sizeof(rpcconn_response_hdr_t)
            - replyHeader.auth_length;

        HUnlock(dataHandle);
        SetHandleSize(dataSize + newDataSize, dataHandle);
        if (toolerror())
            goto error;
        
        HLock(dataHandle);
        memcpy(*dataHandle + dataSize, reply.stub_data, newDataSize);
        dataSize += newDataSize;
    } while (!(replyHeader.pfc_flags & PFC_LAST_FRAG));

    if (dataSize == 0)
        goto error;

    return dataHandle;

error:
    DisposeHandle(dataHandle);
    return NULL;

#undef reply
#undef replyHeader
}
