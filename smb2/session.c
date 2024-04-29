#include "defs.h"

#include <memory.h>
#include <tcpip.h>
#include <gsos.h>
#include <orca.h>
#include "smb2/session.h"
#include "smb2/connection.h"
#include "smb2/treeconnect.h"
#include "utils/alloc.h"
#include "smb2/smb2.h"
#include "auth/auth.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"
#include "driver/driver.h"

Session sessions[NDIBS];

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
        sess->connection = NULL;
    }
}

Session *Session_Alloc(void) {
    unsigned i;
    
    for (i = 0; i < ARRAY_LENGTH(sessions); i++) {
        if (sessions[i].refCount == 0 && sessions[i].connection == NULL)
            return &sessions[i];
    }
    
    return NULL;
}

/*
 * Perform the SMB2 SESSION_SETUP negotiation with the server.
 * session->connection and session->authInfo should be initialized before
 * calling this function.  Returns an error code, or 0 for success.
 */
Word SessionSetup(Session *session) {
    static ReadStatus result;
    static AuthState authState;
    static size_t authSize;
    static unsigned char *previousAuthMsg;
    static size_t previousAuthSize;
    static unsigned char cmac_key[16];
    static uint64_t previousSessionId;
    
    previousSessionId = session->sessionId;
    session->sessionId = 0;

    InitAuth(&authState, &session->authInfo);
    previousAuthMsg = NULL;
    previousAuthSize = 0;

    if (session->hmacSigningContext != NULL) {
        DisposeHandle(FindHandle((void*)session->hmacSigningContext));
        session->hmacSigningContext = NULL;
    }

    while (1) {
        authSize = DoAuthStep(&authState, previousAuthMsg,
            previousAuthSize, sessionSetupRequest.Buffer);
        if (authSize == (size_t)-1) {
            // TODO handle errors
            session->sessionId = previousSessionId;
            return networkError;
        }

        sessionSetupRequest.Flags = 0;
        sessionSetupRequest.SecurityMode = 0;
        sessionSetupRequest.Capabilities = 0;
        sessionSetupRequest.Channel = 0;
        sessionSetupRequest.SecurityBufferOffset = 
            sizeof(SMB2Header) + sizeof(SMB2_SESSION_SETUP_Request);
        sessionSetupRequest.SecurityBufferLength = authSize;
        sessionSetupRequest.PreviousSessionId = previousSessionId;

        fakeDIB.session = session;
        result = SendRequestAndGetResponse(&fakeDIB, SMB2_SESSION_SETUP,
            sizeof(sessionSetupRequest) + authSize);
        
        if (result == rsDone) {
            if (session->connection->wantSigning &&
                (sessionSetupResponse.SessionFlags &
                    (SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL)) == 0)
            {
                if (session->connection->dialect <= SMB_21) {
                    Handle ctxHandle = NewHandle(
                        sizeof(struct hmac_sha256_context), userid(), 0x8015, 0);
                    if (toolerror()) {
                        // TODO clean up on errors?
                        session->sessionId = previousSessionId;
                        return outOfMem;
                    }
                
                    session->signingRequired = true;
                    session->hmacSigningContext = (void*)*ctxHandle;
                
                    hmac_sha256_init(session->hmacSigningContext,
                        authState.signKey,
                        16);
                } else {
                    Handle ctxHandle = NewHandle(
                        sizeof(struct aes_cmac_context), userid(), 0x8015, 0);
                    if (toolerror()) {
                        // TODO clean up on errors?
                        session->sessionId = previousSessionId;
                        return outOfMem;
                    }
                
                    session->signingRequired = true;
                    session->cmacSigningContext = (void*)*ctxHandle;

                    /*
                     * Compute signing key using a key-derivation function,
                     * as specified in [MS-SMB2] sections 3.1.4.2 and 3.2.5.3.
                     */
                    if (session->connection->dialect <= SMB_302) {
                        hmac_sha256_kdf_ctr((struct hmac_sha256_context *)gbuf,
                            authState.signKey, 16, 128, cmac_key,
                            "SMB2AESCMAC", 12, "SmbSign", 8);
                    } else {
                        UNIMPLEMENTED
                    }
                    aes_cmac_init(session->cmacSigningContext, cmac_key);
                }
            }
            
            session->sessionId = msg.smb2Header.SessionId;
            return 0;
        } else if (result == rsMoreProcessingRequired) {
            if (!VerifyBuffer(
                sessionSetupResponse.SecurityBufferOffset,
                sessionSetupResponse.SecurityBufferLength)) {
                // TODO clean up on errors?
                session->sessionId = previousSessionId;
                return networkError;
            }
            
            session->sessionId = msg.smb2Header.SessionId;
            
            previousAuthMsg = (unsigned char *)&msg.smb2Header + 
                sessionSetupResponse.SecurityBufferOffset;
            previousAuthSize = sessionSetupResponse.SecurityBufferLength;
        } else {
            // TODO clean up on errors?
            session->sessionId = previousSessionId;
            return invalidAccess;
        }
    };
}

Word Session_Reconnect(Session *session) {
    Word result, result2;
    unsigned i;

    session->signingRequired = false;
    
    result = SessionSetup(session);
    if (result != 0)
        return result;

    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].extendedDIBPtr != NULL && dibs[i].session == session) {
            result2 = TreeConnect_Reconnect(&dibs[i]);
            if (result2 != 0 && result == 0)
                result = result2;
        }
    }
    
    return result;
}

