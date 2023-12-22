#include "defs.h"
#include <stddef.h>
#include <string.h>
#include <gsos.h>
#include "smb2.h"
#include "fstspecific.h"
#include "driver.h"

#ifndef devListFull
#define devListFull 0x0068
#endif

Word SMB_Mount(SMBMountRec *pblock, void *gsosdp, Word pcount) {
    static ReadStatus result;
    unsigned dibIndex;

    if (pblock->pCount != 6)
        return invalidPcount;

    for (dibIndex = 0; dibIndex < NDIBS; dibIndex++) {
        if (dibs[dibIndex].extendedDIBPtr == 0)
            break;
    }
    if (dibIndex == NDIBS)
        return devListFull;

    treeConnectRequest.Reserved = 0;
    treeConnectRequest.PathOffset =
        sizeof(SMB2Header) + offsetof(SMB2_TREE_CONNECT_Request, Buffer);
    treeConnectRequest.PathLength = pblock->shareNameSize;
    memcpy(treeConnectRequest.Buffer, pblock->shareName, pblock->shareNameSize);
    
    result = SendRequestAndGetResponse((Session*)pblock->sessionID,
        SMB2_TREE_CONNECT, 0,
        sizeof(treeConnectRequest) + pblock->shareNameSize);
    if (result != rsDone) {
        return networkError;
    }

    dibs[dibIndex].treeId = msg.smb2Header.TreeId;
    dibs[dibIndex].switched = true;
    dibs[dibIndex].extendedDIBPtr = &dibs[dibIndex].treeId;

    pblock->devNum = dibs[dibIndex].DIBDevNum;
    return 0;
}
