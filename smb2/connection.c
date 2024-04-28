#include "defs.h"

#include <tcpip.h>
#include "smb2/connection.h"
#include "utils/alloc.h"
#include "driver/driver.h"

DIB fakeDIB = {0};

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
