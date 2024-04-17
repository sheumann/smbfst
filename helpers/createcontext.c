#include "defs.h"
#include <stdbool.h>
#include <string.h>
#include "smb2.h"
#include "endian.h"
#include "helpers/createcontext.h"

/*
 * The length of create context names that we support.  Create context names
 * are actually variable length, but all the ones we care about are 4 bytes.
 */
#define CTX_NAME_LEN 4

/*
 * Add a create context to an otherwise-assembled SMB2 CREATE request.
 *
 * name gives the name of the context (must be 4 bytes).
 * data and dataLen specify the buffer with the context data.
 * *msgLen is the length of the CREATE request, which will be updated.
 *
 * Returns true on success, false on failure (not enough space).
 */
bool AddCreateContext(uint32_t name, const void *data, uint16_t dataLen,
    uint16_t *msgLen) {

    uint32_t pos;
    uint32_t newLen;
    SMB2_CREATE_CONTEXT *ctx;
    
    // calculate position of new context in message (8-byte aligned)
    pos = ((uint32_t)*msgLen + 7) & 0xFFFFFFF8;
    
    // calculate message length with context, and check if it's too big
    newLen = pos + sizeof(SMB2_CREATE_CONTEXT) + dataLen;
    if (newLen > sizeof(msg.body))
        return false;
    
    // zero out any padding added for alignment
    *(uint64_t*)(&msg.body[*msgLen]) = 0;
    
    ctx = (SMB2_CREATE_CONTEXT *)(&msg.body[pos]);

    ctx->Next = 0;
    ctx->NameOffset = offsetof(SMB2_CREATE_CONTEXT, Name);
    ctx->NameLength = sizeof(ctx->Name);
    ctx->Reserved = 0;
    ctx->DataOffset = offsetof(SMB2_CREATE_CONTEXT, Data);
    ctx->DataLength = dataLen;
    ctx->Name = hton32(name);
    ctx->Padding = 0;
    memcpy(ctx->Data, data, dataLen);

    if (createRequest.CreateContextsOffset == 0) {
        createRequest.CreateContextsOffset = sizeof(SMB2Header) + pos;
        createRequest.CreateContextsLength =
            sizeof(SMB2_CREATE_CONTEXT) + dataLen;
    } else {
        ctx = (SMB2_CREATE_CONTEXT *)
            ((char*)&msg.smb2Header + createRequest.CreateContextsOffset);
        while (ctx->Next != 0) {
            ctx = (SMB2_CREATE_CONTEXT *)((char*)ctx + ctx->Next);
        }
        ctx->Next = pos - ((char*)ctx - (char*)&msg.body);
        createRequest.CreateContextsLength += newLen - *msgLen;
    }

    *msgLen = newLen;

    return true;
}

/*
 * This finds a create context with the given name within createResponse.
 * It returns a pointer to the data portion of the create context, and
 * sets *dataLen to the length of the data portion.  If the context is not
 * found or an error is encountered, it returns a null pointer.
 */
void *GetCreateContext(uint32_t name, uint16_t *dataLen) {
    SMB2_CREATE_CONTEXT *ctx;
    uint16_t remainingSize, ctxSize;

    name = hton32(name);

    if (createResponse.CreateContextsOffset > 0xffff)
        return 0;
    if (createResponse.CreateContextsLength > 0xffff)
        return 0;
    if (!VerifyBuffer(
        createResponse.CreateContextsOffset,
        createResponse.CreateContextsLength))
    {
        return 0;
    }
    
    ctx = (SMB2_CREATE_CONTEXT *)(
        (uint8_t*)&msg.smb2Header + createResponse.CreateContextsOffset);
    remainingSize = createResponse.CreateContextsLength;
    
    do {
        if (remainingSize < offsetof(SMB2_CREATE_CONTEXT, Name))
            return 0;
        if (ctx->Next >= remainingSize)
            return 0;
        ctxSize = ctx->Next ? ctx->Next : remainingSize;
        
        if ((uint32_t)ctx->NameOffset + ctx->NameLength > ctxSize)
            return 0;
        if (ctx->DataLength > ctxSize)
            return 0;
        if ((uint32_t)ctx->DataOffset + ctx->DataLength > ctxSize)
            return 0;
        
        if (ctx->NameLength != CTX_NAME_LEN)
            goto next;
        if (memcmp(&name, (char*)ctx + ctx->NameOffset, CTX_NAME_LEN) != 0)
            goto next;

        // we have the right context -- return its data
        *dataLen = ctx->DataLength;
        return (char*)ctx + ctx->DataOffset;

next:
        if (ctx->Next == 0) {
            return 0;
        } else {
            remainingSize -= ctx->Next;
            ctx = (void*)((char*)ctx + ctx->Next);
        }
    } while (1);
}
