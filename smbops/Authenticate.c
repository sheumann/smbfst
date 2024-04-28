#include "defs.h"
#include <types.h>
#include <stddef.h>
#include <string.h>
#include <memory.h>
#include <orca.h>
#include <gsos.h>
#include "gsos/gsosdata.h"
#include "fst/fstspecific.h"
#include "smb2/smb2.h"
#include "auth/auth.h"
#include "auth/ntlm.h"
#include "utils/alloc.h"
#include "smb2/connection.h"

Word SMB_Authenticate(SMBAuthenticateRec *pblock, void *gsosdp, Word pcount) {
    Connection *connection = (Connection *)pblock->connectionID;
    Session *session;
    Word result;
    
    session = smb_malloc(sizeof(Session));
    if (session == NULL)
        return outOfMem;

    memset(session, 0, sizeof(Session));
    session->connection = connection;

    // Set up auth info for session, including NTLMv2 hash
    if (!GetNTLMv2Hash(pblock->passwordSize, pblock->password,
        pblock->userNameSize, pblock->userName,
        pblock->userDomainSize, pblock->userDomain,
        session->authInfo.ntlmv2Hash)) {
        result = outOfMem;
        goto finish;
    }

    session->authInfo.userNameSize = pblock->userNameSize;
    if (pblock->userNameSize != 0) {
        session->authInfo.userName = smb_malloc(pblock->userNameSize);
        if (session->authInfo.userName == NULL) {
            result = outOfMem;
            goto finish;
        }
        memcpy(session->authInfo.userName, pblock->userName,
            pblock->userNameSize);
    }
    
    session->authInfo.userDomainSize = pblock->userDomainSize;
    if (pblock->userDomainSize != 0) {
        session->authInfo.userDomain = smb_malloc(pblock->userDomainSize);
        if (session->authInfo.userDomain == NULL) {
            result = outOfMem;
            goto finish;
        }
        memcpy(session->authInfo.userDomain, pblock->userDomain,
            pblock->userDomainSize);
    }

    result = SessionSetup(session);

finish:
    if (result == 0) {
        Connection_Retain(connection);
        session->refCount = 1;
        pblock->sessionID = (LongWord)session;
        return 0;
    } else {
        smb_free(session->authInfo.userName);
        smb_free(session->authInfo.userDomain);
        smb_free(session);
    }
    return result;
}
