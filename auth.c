#include <string.h>

#include "auth.h"
#include "ntlm.h"

/* OID for SPNEGO, encoded as per RFC 2743 sec. 3.1 (items 3-5) */
static const unsigned char SPNEGO_OID[] =
    {0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02};

static const unsigned char NTLMSSP_OID[] = 
    {0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};

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

void InitAuth(AuthState *state) {
    memset(state, 0, sizeof(*state));
}

size_t DoAuthStep(AuthState *state, const unsigned char *previousMsg,
                  unsigned char *msgBuf) {
    unsigned char *msgPtr = msgBuf;

    switch (state->step++) {
    case 0:
        /* GSS-API token; see RFC 2743 sec. 3.1 */
        /* note: this assumes total token length <= 129 */
        *msgPtr++ = 0x60;
        *msgPtr++ = sizeof(SPNEGO_OID) + 4 + 4 + sizeof(NTLMSSP_OID) +
            4 + sizeof(negotiateMessage);
        
        /* OID for SPNEGO */
        memcpy(msgPtr, SPNEGO_OID, sizeof(SPNEGO_OID));
        msgPtr += sizeof(SPNEGO_OID);
    
        /* SPNEGO negTokenInit (RFC 4178 sec. 4.2.1), encoded per X.690 DER */
        
        *msgPtr++ = 0xA0; /* constructed */
        *msgPtr++ = 2 + 4 + sizeof(NTLMSSP_OID) + 4 + sizeof(negotiateMessage);
        *msgPtr++ = 0x30; /* SEQUENCE */
        *msgPtr++ = 4 + sizeof(NTLMSSP_OID) + 4 + sizeof(negotiateMessage);
        
        /* mechTypes */
        *msgPtr++ = 0xA0; /* constructed */
        *msgPtr++ = 2 + sizeof(NTLMSSP_OID);
        *msgPtr++ = 0x30; /* SEQUENCE OF */
        *msgPtr++ = sizeof(NTLMSSP_OID);
        memcpy(msgPtr, NTLMSSP_OID, sizeof(NTLMSSP_OID));
        msgPtr += sizeof(NTLMSSP_OID);
        
        /* mechToken */
        *msgPtr++ = 0xA2; /* constructed [2] */
        *msgPtr++ = 2 + sizeof(negotiateMessage);
        *msgPtr++ = 0x04; /* OCTETSTRING */
        *msgPtr++ = sizeof(negotiateMessage);
        
        /* NTLM NEGOTIATE_MESSAGE */
        memcpy(msgPtr, &negotiateMessage, sizeof(negotiateMessage));
        msgPtr += sizeof(negotiateMessage);
        
        return msgPtr - msgBuf;

    case 1:
        /* TODO */
        return (size_t)-1;
        
    default:
        return (size_t)-1;
    }
}
