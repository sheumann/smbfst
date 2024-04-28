#include "defs.h"

#include <memory.h>
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
        fakeDIB.session = sess;
        SendRequestAndGetResponse(&fakeDIB, SMB2_LOGOFF, sizeof(logoffRequest));
        // ignore errors from logoff

        if (sess->hmacSigningContext != NULL)
            DisposeHandle(FindHandle((Pointer)sess->hmacSigningContext));

        Connection_Release(sess->connection);
        
        smb_free(sess->authInfo.userName);
        smb_free(sess->authInfo.userDomain);
        smb_free(sess);
    }
}
