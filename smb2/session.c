#include "defs.h"

#include <tcpip.h>
#include "smb2/session.h"
#include "smb2/connection.h"
#include "utils/alloc.h"
#include "smb2/smb2.h"

void Session_Retain(Session *sess) {
    ++sess->refCount;
}

void Session_Release(Session *sess) {
    if (--sess->refCount == 0) {
        logoffRequest.Reserved = 0;
        SendRequestAndGetResponse(sess, SMB2_LOGOFF, 0, sizeof(logoffRequest));
        // ignore errors from logoff

        Connection_Release(sess->connection);
        smb_free(sess);
    }
}
