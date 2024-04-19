#include "defs.h"

#include <tcpip.h>
#include "smb2/connection.h"
#include "utils/alloc.h"

void Connection_Retain(Connection *conn) {
    ++conn->refCount;
}

void Connection_Release(Connection *conn) {
    if (--conn->refCount == 0) {
        TCPIPAbortTCP(conn->ipid);
        TCPIPLogout(conn->ipid);
        smb_free(conn);
    }
}
