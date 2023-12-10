#include <string.h>

#include "auth.h"
#include "ntlm.h"

// Type we use for length of items in X.690 encoding
typedef uint16_t length_t;

/* OID for SPNEGO, encoded as per RFC 2743 sec. 3.1 (items 3-5) */
static const unsigned char SPNEGO_OID[] =
    {0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02};

static const unsigned char NTLMSSP_OID[] = 
    {0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};

// SPNEGO negState enumeration (see RFC 4178)
enum {
    SPNEGO_accept_completed = 0,
    SPNEGO_accept_incomplete = 1,
    SPNEGO_reject = 2,
    SPNEGO_request_mic = 3,
};



void InitAuth(AuthState *state) {
    memset(state, 0, sizeof(*state));
}

/*
 * Get the length of an item in X.690 DER encoding.
 */
length_t GetX690Length(const unsigned char **bufPtrPtr,
    const unsigned char *bufEnd) {
    length_t length;
    length_t i;

    if (*bufPtrPtr == bufEnd)
        return 0;
    length = *(*bufPtrPtr)++;
    if (length & 0x80) {
        length &= 0x7F;
        if (length > sizeof(length_t))
            return 0; // too big
        for (i = length, length = 0; i != 0; i--) {
            if (*bufPtrPtr == bufEnd)
                return 0;
            length <<= 8;
            length |= *(*bufPtrPtr)++;
        }
    }
    if (length > bufEnd - *bufPtrPtr)
        return 0; //invalid size
    return length;
}

void WriteX690Length(unsigned char **bufPtrPtr, uint16_t val) {
    if (val < 128) {
        *(*bufPtrPtr)++ = val;
    } else {
        *(*bufPtrPtr)++ = 0x82;
        *(*bufPtrPtr)++ = val >> 8;
        *(*bufPtrPtr)++ = val & 0xFF;
    }
}

/*
 * Do one step of an authentication exchange.
 *
 * state - state of authentication exchange
 * previousMsg - previous message received in the exchange, if any
 * previousSize - size of previousMsg
 * msgBuf - buffer to hold new message (may overlap previousMsg)
 *
 * Returns size of new message, or (size_t)-1 on error.
 */
size_t DoAuthStep(AuthState *state, const unsigned char *previousMsg,
                  uint16_t previousSize, unsigned char *msgBuf) {
    unsigned char *msgPtr = msgBuf;
    unsigned char *prevMsgPtr;
    size_t itemSize;
    unsigned char *authMsgPtr;
    unsigned char *mechListPtr;
    unsigned char *mechListMICPtr;
    size_t mechListMICSize;
    static NTLM_Context ntlmContext;

    switch (state->step++) {
    case 0:
        /* GSS-API token; see RFC 2743 sec. 3.1 */
        /* note: this assumes total token length <= 129 */
        *msgPtr++ = 0x60;
        *msgPtr++ = sizeof(SPNEGO_OID) + 4 + 4 + sizeof(NTLMSSP_OID) +
            4 + sizeof(NTLM_NEGOTIATE_MESSAGE);
        
        /* OID for SPNEGO */
        memcpy(msgPtr, SPNEGO_OID, sizeof(SPNEGO_OID));
        msgPtr += sizeof(SPNEGO_OID);
    
        /* SPNEGO negTokenInit (RFC 4178 sec. 4.2.1), encoded per X.690 DER */
        
        *msgPtr++ = 0xA0; /* constructed */
        *msgPtr++ =
            2 + 4 + sizeof(NTLMSSP_OID) + 4 + sizeof(NTLM_NEGOTIATE_MESSAGE);
        *msgPtr++ = 0x30; /* SEQUENCE */
        *msgPtr++ =
            4 + sizeof(NTLMSSP_OID) + 4 + sizeof(NTLM_NEGOTIATE_MESSAGE);
        
        /* mechTypes */
        *msgPtr++ = 0xA0; /* constructed [0] */
        *msgPtr++ = 2 + sizeof(NTLMSSP_OID);
        mechListPtr = msgPtr;
        *msgPtr++ = 0x30; /* SEQUENCE OF */
        *msgPtr++ = sizeof(NTLMSSP_OID);
        memcpy(msgPtr, NTLMSSP_OID, sizeof(NTLMSSP_OID));
        msgPtr += sizeof(NTLMSSP_OID);
        state->mechListSize = msgPtr - mechListPtr;
        
        // Save mechList for later computation of mechListMIC
        memcpy(state->mechList, mechListPtr, state->mechListSize);
        
        /* mechToken */
        *msgPtr++ = 0xA2; /* constructed [2] */
        *msgPtr++ = 2 + sizeof(NTLM_NEGOTIATE_MESSAGE);
        *msgPtr++ = 0x04; /* OCTET STRING */
        *msgPtr++ = sizeof(NTLM_NEGOTIATE_MESSAGE);
        
        /* NTLM NEGOTIATE_MESSAGE */
        NTLM_GetNegotiateMessage(&ntlmContext, msgPtr);
        msgPtr += sizeof(NTLM_NEGOTIATE_MESSAGE);
        
        return msgPtr - msgBuf;

    case 1:
        prevMsgPtr = previousMsg;
        /* Require a previous message of sufficient size */
        if (previousSize < 4 + 5 + 2 + sizeof(NTLMSSP_OID) + 4 + 
            sizeof(NTLM_CHALLENGE_MESSAGE))
            return (size_t)-1;
        
        /* expect constructed [1] encoding and get size */
        if (*prevMsgPtr++ != 0xA1)
            return (size_t)-1;
        itemSize = GetX690Length(&prevMsgPtr, previousMsg + previousSize);
        if (itemSize == 0)
            return (size_t)-1; //invalid size
        
        /* expect sequence and get size */
        if (*prevMsgPtr++ != 0x30)
            return (size_t)-1;
        itemSize = GetX690Length(&prevMsgPtr, previousMsg + previousSize);
        if (itemSize == 0)
            return (size_t)-1; //invalid size
        
        /* expect negState = accept-incomplete */
        if (*prevMsgPtr++ != 0xA0 || // constructed [0]
            *prevMsgPtr++ != 0x03 ||
            *prevMsgPtr++ != 0x0A || // ENUMERATED
            *prevMsgPtr++ != 0x01 ||
            *prevMsgPtr++ != SPNEGO_accept_incomplete)
            return (size_t)-1;

        /* expect supportedMech = NTLMSSP */
        if (*prevMsgPtr++ != 0xA1 || // constructed [1]
            *prevMsgPtr++ != 0x0C)
            return (size_t)-1;
        if (memcmp(prevMsgPtr, NTLMSSP_OID, sizeof(NTLMSSP_OID)) != 0)
            return (size_t)-1;
        prevMsgPtr += sizeof(NTLMSSP_OID);
        
        /* expect constructed [2] encoding for responseToken */
        if (*prevMsgPtr++ != 0xA2) // constructed [2]
            return (size_t)-1;
        itemSize = GetX690Length(&prevMsgPtr, previousMsg + previousSize);
        if (itemSize == 0)
            return (size_t)-1; //invalid size
        
        /* expect octet string for responseToken */
        if (*prevMsgPtr++ != 0x04) // constructed [2]
            return (size_t)-1;
        itemSize = GetX690Length(&prevMsgPtr, previousMsg + previousSize);
        if (itemSize == 0)
            return (size_t)-1; //invalid size

        /* Get NTLM AUTHENTICATE_MESSAGE */
        authMsgPtr = NTLM_HandleChallenge(&ntlmContext,
            (NTLM_CHALLENGE_MESSAGE *)prevMsgPtr, itemSize, &itemSize);
        if (authMsgPtr == NULL)
            return (size_t)-1;

        mechListMICPtr = NTLM_GetMechListMIC(&ntlmContext, state->mechList,
            state->mechListSize, &mechListMICSize);
        
        // This ensures sizes are multi-byte
        // TODO handle more elegantly, making sure not to read beyond buffer
        if (itemSize < 256)
            itemSize = 256;
        
        *msgPtr++ = 0xA1; // constructed [1] (negTokenResp)
        WriteX690Length(&msgPtr, 12+itemSize+4+mechListMICSize);
        *msgPtr++ = 0x30; // sequence
        WriteX690Length(&msgPtr, 8+itemSize+4+mechListMICSize);

        /* responseToken */
        *msgPtr++ = 0xA2; // constructed [2]
        WriteX690Length(&msgPtr, itemSize+4);
        *msgPtr++ = 0x04; // OCTET STRING
        WriteX690Length(&msgPtr, itemSize);

        memcpy(msgPtr, authMsgPtr, itemSize);
        msgPtr += itemSize;

        /* mechListMIC */
        *msgPtr++ = 0xA3; // constructed [3]
        WriteX690Length(&msgPtr, mechListMICSize+2);
        *msgPtr++ = 0x04; // OCTET STRING
        WriteX690Length(&msgPtr, mechListMICSize);

        memcpy(msgPtr, mechListMICPtr, mechListMICSize);
        msgPtr += mechListMICSize;

        return msgPtr - msgBuf;
        
    default:
        return (size_t)-1;
    }
}
