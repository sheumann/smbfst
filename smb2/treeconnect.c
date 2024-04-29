#include "defs.h"
#include <string.h>
#include <gsos.h>
#include "smb2/smb2.h"
#include "smb2/treeconnect.h"
#include "driver/driver.h"

Word TreeConnect(DIB *dib) {
    ReadStatus result;

    treeConnectRequest.Reserved = 0;
    treeConnectRequest.PathOffset =
        sizeof(SMB2Header) + offsetof(SMB2_TREE_CONNECT_Request, Buffer);
    treeConnectRequest.PathLength = dib->shareNameSize;
    memcpy(treeConnectRequest.Buffer, dib->shareName, dib->shareNameSize);

    result = SendRequestAndGetResponse(dib, SMB2_TREE_CONNECT,
        sizeof(treeConnectRequest) + dib->shareNameSize);
    if (result != rsDone) {
        return networkError;
    }
    
    dib->treeId = msg.smb2Header.TreeId;
    return 0;
}

Word TreeConnect_Reconnect(DIB *dib) {
    // TODO handle reconnecting files, or block reconnect if there are open files

    return TreeConnect(dib);
}