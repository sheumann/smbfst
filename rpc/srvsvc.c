#define USE_BLANK_SEG
#include "defs.h"
#include <uchar.h>
#include <stdio.h>
#include <memory.h>
#include "rpc/rpc.h"
#include "rpc/ndr.h"
#include "rpc/srvsvc.h"
#include "rpc/srvsvcproto.h"
#include "utils/guid.h"

// UUID and version for SRVSVC (see [MS-SRVS])
p_syntax_id_t srvsvcSyntax =
    {.if_uuid = GUID(4b324fc8,1670,01d3,1278,5a47bf6ee188), 3};

/*
 * This returns NULL on failure.  Otherwise, it returns a locked handle to a
 * ShareInfoRec containing information about the shares on the server.
 * (The strings referenced in the ShareInfoRec are held later within the same
 * handle.)  It is the caller's responsibility to dispose of the handle.
 */
Handle EnumerateShares(Word devNum) {
    Handle responseData;
    RPCConnection rpcConn;
    uint32_t assocGroupID;
    SHARE_ENUM_STRUCT *infoPtr;
    SHARE_INFO_1_CONTAINER *si1ContainerPtr;
    uint32_t entryCount;
    NDR_CONFORMANT_ARRAY(SHARE_INFO_1) *si1ArrayPtr;
    SHARE_INFO_1 *si1Array;
    NDR_CONFORMANT_VARYING_STRING(char16_t) *str;
    uint32_t i;

    static char path[15];

    snprintf(path, sizeof(path), ".d%u:srvsvc", devNum);
    if (!ConnectRPC(&rpcConn, path))
        return NULL;

    assocGroupID = RPCBind(&rpcConn, &srvsvcSyntax);
    if (assocGroupID == 0) {
        DisconnectRPC(&rpcConn);
        return NULL;
    }
    
    static unsigned char msgBuf[32];
    NDRBufInfo ndr;

    static const SHARE_ENUM_STRUCT infoStruct = {
        .Level = LEVEL_1,
        .ShareInfo.tag = LEVEL_1,
        .ShareInfo.data.Level1 = NDR_ARBITRARY
    };
    
    static const SHARE_INFO_1_CONTAINER si1Container = {
        .EntriesRead = 0,
        .Buffer = NDR_NULL
    };

    InitNDRBuf(&ndr, msgBuf, sizeof(msgBuf));
    NDRWritePtr(&ndr, NDR_NULL);                     // ServerName
    NDRWrite(&ndr, &infoStruct, sizeof(infoStruct)); // InfoStruct
    NDRWrite(&ndr, &si1Container, sizeof(si1Container));
    /*
     * macOS won't accept any other value for PreferedMaximumLength
     */
    NDRWriteI32(&ndr, 0xFFFFFFFF);                   // PreferedMaximumLength
    NDRWritePtr(&ndr, NDR_NULL);                     // ResumeHandle
    
    responseData =
        RPCRequest(&rpcConn, NetrShareEnum_opnum, msgBuf, NDRDataSize(&ndr));

    DisconnectRPC(&rpcConn);

    if (responseData == NULL)
        return NULL;
    
    InitNDRBuf(&ndr, *responseData, GetHandleSize(responseData));

    infoPtr = NDRRead(&ndr, sizeof(SHARE_ENUM_STRUCT));
    if (!infoPtr)
        goto error;
    if (infoPtr->Level != LEVEL_1)
        goto error;
    if (infoPtr->ShareInfo.tag != LEVEL_1)
        goto error;
    
    si1ContainerPtr = NDRRead(&ndr, sizeof(SHARE_INFO_1_CONTAINER));
    if (!si1ContainerPtr)
        goto error;
    entryCount = si1ContainerPtr->EntriesRead;
    
    si1ArrayPtr = NDRRead(&ndr, sizeof(NDR_CONFORMANT_ARRAY(SHARE_INFO_1)));
    if (!si1ArrayPtr)
        goto error;
    if (si1ArrayPtr->maxCount != entryCount)
        goto error;
    
    if (entryCount > UINT32_MAX / sizeof(SHARE_INFO_1))
        goto error;
    si1Array = NDRRead(&ndr, entryCount * sizeof(SHARE_INFO_1));
    
    for (i = 0; i < entryCount; i++) {
        if (!NDRAlign(&ndr, 4))
            goto error;
        str = NDRRead(&ndr, sizeof(NDR_CONFORMANT_VARYING_STRING(char16_t)));
        if (str->maxCount != str->actualCount || str->maxCount == 0)
            goto error;
        if (str->offset != 0)
            goto error;
        if (str->actualCount > UINT32_MAX/sizeof(char16_t))
            goto error;
        NDRRead(&ndr, str->actualCount * sizeof(char16_t));

        si1Array[i].shi1_netname = (uint32_t)&str->actualCount;

        if (!NDRAlign(&ndr, 4))
            goto error;
        str = NDRRead(&ndr, sizeof(NDR_CONFORMANT_VARYING_STRING(char16_t)));
        if (str->maxCount != str->actualCount || str->maxCount == 0)
            goto error;
        if (str->offset != 0)
            goto error;
        if (str->actualCount > UINT32_MAX/sizeof(char16_t))
            goto error;
        NDRRead(&ndr, str->actualCount * sizeof(char16_t));

        si1Array[i].shi1_remark = (uint32_t)&str->actualCount;
    }

    return responseData;

error:
    DisposeHandle(responseData);
    return NULL;
}
