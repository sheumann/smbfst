#include <string.h>

#include "ntlm.h"

void NTLM_GetNegotiateMessage(unsigned char *buf) {
    static NTLM_NEGOTIATE_MESSAGE negotiateMessage = {
        .Signature = "NTLMSSP",
        .MessageType = NtLmNegotiate,
        .NegotiateFlags = 
            NTLMSSP_NEGOTIATE_KEY_EXCH +
            NTLMSSP_NEGOTIATE_128 +
            NTLMSSP_NEGOTIATE_TARGET_INFO +
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY +
            NTLMSSP_NEGOTIATE_ALWAYS_SIGN +
            NTLMSSP_NEGOTIATE_NTLM +
            NTLMSSP_NEGOTIATE_SIGN +
            NTLMSSP_REQUEST_TARGET +
            NTLMSSP_NEGOTIATE_UNICODE,
        .DomainNameFields = {0,0,0},
        .WorkstationFields = {0,0,0},
        .Version = {0},
    };

    memcpy(buf, &negotiateMessage, sizeof(negotiateMessage));
}

int NTLM_HandleChallenge(const NTLM_CHALLENGE_MESSAGE *challengeMsg,
                          uint16_t challengeSize) {
    // Check that this is a valid challenge message
    if (challengeSize < sizeof(NTLM_CHALLENGE_MESSAGE))
        return 0;
    if (memcmp(challengeMsg->Signature, "NTLMSSP", 8) != 0)
        return 0;
    if (challengeMsg->MessageType != NtLmChallenge)
        return 0;
    // TODO verify flags
}
