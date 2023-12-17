#include "defs.h"

#include <tcpip.h>
#include "session.h"
#include "connection.h"
#include "alloc.h"

void Session_Retain(Session *sess) {
    ++sess->refCount;
}

void Session_Release(Session *sess) {
    if (--sess->refCount == 0) {
        // TODO send LOGOFF message to server
        Connection_Release(sess->connection);
        smb_free(sess);
    }
}
