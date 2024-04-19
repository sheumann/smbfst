#include "defs.h"

#include <tcpip.h>
#include "session.h"
#include "connection.h"
#include "alloc.h"
#include "smb2.h"

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
