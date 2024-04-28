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
#include "utils/alloc.h"
#include "smb2/connection.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"

Word SMB_Authenticate(SMBAuthenticateRec *pblock, void *gsosdp, Word pcount) {
    static ReadStatus result;
    static AuthState authState;
    static size_t authSize;
    static unsigned char *previousAuthMsg;
    static size_t previousAuthSize;
    static unsigned char cmac_key[16];
    Connection *connection = (Connection *)pblock->connectionID;
    Session *session;
    
    session = smb_malloc(sizeof(Session));
    if (session == NULL)
        return outOfMem;

    memset(session, 0, sizeof(Session));
    session->connection = connection;

    InitAuth(&authState, pblock);
    previousAuthMsg = NULL;
    previousAuthSize = 0;

    while (1) {
        authSize = DoAuthStep(&authState, previousAuthMsg,
            previousAuthSize, sessionSetupRequest.Buffer);
        if (authSize == (size_t)-1) {
            // TODO handle errors
            smb_free(session);
            return networkError;
        }

        sessionSetupRequest.Flags = 0;
        sessionSetupRequest.SecurityMode = 0;
        sessionSetupRequest.Capabilities = 0;
        sessionSetupRequest.Channel = 0;
        sessionSetupRequest.SecurityBufferOffset = 
            sizeof(SMB2Header) + sizeof(SMB2_SESSION_SETUP_Request);
        sessionSetupRequest.SecurityBufferLength = authSize;
        sessionSetupRequest.PreviousSessionId = 0;

        fakeDIB.session = session;
        result = SendRequestAndGetResponse(&fakeDIB, SMB2_SESSION_SETUP,
            sizeof(sessionSetupRequest) + authSize);
        
        if (result == rsDone) {
            if (connection->wantSigning &&
                (sessionSetupResponse.SessionFlags &
                    (SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL)) == 0)
            {
                if (connection->dialect <= SMB_21) {
                    Handle ctxHandle = NewHandle(
                        sizeof(struct hmac_sha256_context), userid(), 0x8015, 0);
                    if (toolerror()) {
                        // TODO clean up on errors?
                        smb_free(session);
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
                        smb_free(session);
                        return outOfMem;
                    }
                
                    session->signingRequired = true;
                    session->cmacSigningContext = (void*)*ctxHandle;

                    /*
                     * Compute signing key using a key-derivation function,
                     * as specified in [MS-SMB2] sections 3.1.4.2 and 3.2.5.3.
                     */
                    if (connection->dialect <= SMB_302) {
                        hmac_sha256_kdf_ctr((struct hmac_sha256_context *)gbuf,
                            authState.signKey, 16, 128, cmac_key,
                            "SMB2AESCMAC", 12, "SmbSign", 8);
                    } else {
                        UNIMPLEMENTED
                    }
                    aes_cmac_init(session->cmacSigningContext, cmac_key);
                }
            }

            Connection_Retain(connection);
            session->refCount = 1;
            pblock->sessionID = (LongWord)session;
            return 0;
        } else if (result != rsMoreProcessingRequired) {
            // TODO clean up on errors?
            smb_free(session);
            return invalidAccess;
        }

        if (!VerifyBuffer(
            sessionSetupResponse.SecurityBufferOffset,
            sessionSetupResponse.SecurityBufferLength)) {
            // TODO clean up on errors?
            smb_free(session);
            return networkError;
        }
        
        session->sessionId = msg.smb2Header.SessionId;
        
        previousAuthMsg = (unsigned char *)&msg.smb2Header + 
            sessionSetupResponse.SecurityBufferOffset;
        previousAuthSize = sessionSetupResponse.SecurityBufferLength;
    };
}
