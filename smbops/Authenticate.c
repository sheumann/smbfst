/*
 * Copyright (c) 2024 Stephen Heumann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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

/*
 * Authenticate with the server, creating an SMB session.
 *
 * Flags are:
 * AUTH_FLAG_GET_NTLMV2_HASH - Fill in pblock->ntlmv2Hash.
 *  This is done even in most failure cases.
 * AUTH_FLAG_HAVE_NTLMV2_HASH - Indicates pblock->ntlmv2Hash is filled in.
 *  May be set on input. Also set on output if using AUTH_FLAG_GET_NTLMV2_HASH.
 *  pblock->password may be null if this is set on input.
 * AUTH_FLAG_ANONYMOUS - Anonymous connection (blank username & password).
 */
Word SMB_Authenticate(SMBAuthenticateRec *pblock, struct GSOSDP *gsosdp,
    Word pcount) {
    Connection *connection = (Connection *)pblock->connectionID;
    Session *session;
    Word result;
    
    session = Session_Alloc();
    if (session == NULL)
        return outOfMem;

    memset(session, 0, sizeof(Session));
    session->connection = connection;

    // Set up auth info for session, including NTLMv2 hash
    if (pblock->flags & AUTH_FLAG_HAVE_NTLMV2_HASH) {
        memcpy(session->authInfo.ntlmv2Hash, pblock->ntlmv2Hash, 16);
    } else {
        if (!GetNTLMv2Hash(pblock->passwordSize, pblock->password,
            pblock->userNameSize, pblock->userName,
            pblock->userDomainSize, pblock->userDomain,
            session->authInfo.ntlmv2Hash)) {
            result = outOfMem;
            goto finish;
        }
        if (pblock->flags & AUTH_FLAG_GET_NTLMV2_HASH) {
            memcpy(pblock->ntlmv2Hash, session->authInfo.ntlmv2Hash, 16);
            pblock->flags |= AUTH_FLAG_HAVE_NTLMV2_HASH;
        }
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

    session->authInfo.anonymous = (pblock->flags & AUTH_FLAG_ANONYMOUS)
        || (pblock->userNameSize == 0 && pblock->passwordSize == 0);

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
        session->connection = NULL;
    }
    return result;
}
