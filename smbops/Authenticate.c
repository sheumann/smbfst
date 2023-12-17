#include "defs.h"
#include <types.h>

#include <memory.h>
#include <orca.h>
#include <gsos.h>
#include "fstspecific.h"
#include "smb2.h"
#include "auth.h"
#include "crypto/sha256.h"

Word SMB_Authenticate(SMBAuthenticateRec *pblock, void *gsosdp, Word pcount) {
    static ReadStatus result;
    static AuthState authState;
    static size_t authSize;
    static unsigned char *previousAuthMsg;
    static size_t previousAuthSize;
    Connection *connection = (Connection *)pblock->connectionID;

    InitAuth(&authState, pblock);
    previousAuthMsg = NULL;
    previousAuthSize = 0;

    while (1) {
        authSize = DoAuthStep(&authState, previousAuthMsg,
            previousAuthSize, sessionSetupRequest.Buffer);
        if (authSize == (size_t)-1) {
            // TODO handle errors
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

        result = SendRequestAndGetResponse(connection, SMB2_SESSION_SETUP, 0,
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
                        return outOfMem;
                    }
                
                    connection->signingRequired = true;
                    connection->signingContext = (void*)*ctxHandle;
                
                    hmac_sha256_init(connection->signingContext,
                        authState.signKey,
                        16);
                } else {
                    // TODO SMB 3.x version
                    UNIMPLEMENTED
                }
            }
        
            return 0;
        } else if (result != rsMoreProcessingRequired) {
            // TODO clean up on errors?
            return invalidAccess;
        }

        if (!VerifyBuffer(
            sessionSetupResponse.SecurityBufferOffset,
            sessionSetupResponse.SecurityBufferLength)) {
            // TODO clean up on errors?
            return networkError;
        }
        
        connection->sessionId = msg.smb2Header.SessionId;
        
        previousAuthMsg = (unsigned char *)&msg.smb2Header + 
            sessionSetupResponse.SecurityBufferOffset;
        previousAuthSize = sessionSetupResponse.SecurityBufferLength;
    };
}
