#include "defs.h"
#include <stddef.h>
#include <string.h>
#include <gsos.h>
#include "smb2.h"
#include "fstspecific.h"

Word SMB_Mount(SMBMountRec *pblock, void *gsosdp, Word pcount) {
    static ReadStatus result;

    if (pblock->pCount != 6)
        return invalidPcount;

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
    
    // TODO mount this share as a GS/OS device
    // (using msg.smb2Header.TreeId)

    return 0;
}
