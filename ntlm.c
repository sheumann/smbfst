#include <stddef.h>
#include <string.h>
#include <uchar.h>

#include "defs.h"
#include "crypto/md4.h"
#include "crypto/md5.h"
#include "crypto/rc4.h"

#include "ntlm.h"
#include "authinfo.h"

static const NTLM_NEGOTIATE_MESSAGE negotiateMessage = {
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

/*
 * Compute NT one-way function v2 for given user, user domain, and password
 *
 * Strings are in UTF-16, but sizes are byte counts.
 * User string must already be in uppercase.
 */
void NTOWFv2(uint16_t passwordSize, char16_t password[],
             uint16_t userSize, char16_t userUpperCase[],
             uint16_t userDomainSize, char16_t userDomain[],
             unsigned  char *result) {
    // TODO allocate contexts off-stack
    struct md4_context md4_context;
    struct hmac_md5_context hmac_md5_context;
    
    md4_init(&md4_context);
    md4_update(&md4_context, (const void*)password, passwordSize);
    md4_finalize(&md4_context);
    
    hmac_md5_init(&hmac_md5_context,
        md4_context.hash, sizeof(md4_context.hash));
    hmac_md5_update(&hmac_md5_context, (const void*)userUpperCase, userSize);
    hmac_md5_update(&hmac_md5_context, (const void*)userDomain, userDomainSize);
    hmac_md5_finalize(&hmac_md5_context);
    
    memcpy(result, hmac_md5_context.u[0].ctx.hash, 16);
}

void NTLM_GetNegotiateMessage(unsigned char *buf) {

    memcpy(buf, &negotiateMessage, sizeof(negotiateMessage));
}

// TODO set appropriate size (dynamically allocate?)
static unsigned char ntlmResponseBuf[
    sizeof(NTLM_AUTHENTICATE_MESSAGE)+sizeof(NTLMv2_CLIENT_CHALLENGE)+1000];
#define authMsg (*(NTLM_AUTHENTICATE_MESSAGE*)ntlmResponseBuf)


static const void *NTLM_GetTargetInfo(
    const NTLM_CHALLENGE_MESSAGE *challengeMsg, uint16_t challengeSize,
    uint16_t avId, uint16_t *size) {
    AV_PAIR *avPair;
    uint32_t offset = challengeMsg->TargetInfoFields.BufferOffset;
    
    while (1) {
        if (offset == 0 || offset > challengeSize - 4)
            goto not_found;
    
        avPair = (AV_PAIR *)((const char *)challengeMsg + offset);
        if (avPair->AvId == MsvAvEOL)
            goto not_found;
    
        if (offset + avPair->AvLen + 4 > challengeSize)
            goto not_found;
    
        if (avPair->AvId == avId) {
            *size = avPair->AvLen;
            return (const char *)challengeMsg + offset + 4;
        }

        offset += avPair->AvLen + 4;
    }

not_found:
    *size = 0;
    return NULL;
}

unsigned char *NTLM_HandleChallenge(const NTLM_CHALLENGE_MESSAGE *challengeMsg,
                            uint16_t challengeSize, size_t *resultSize) {
    uint16_t infoSize;
    const void *infoPtr;
    static uint8_t tempBuf[8+8+8+4+1000]; // TODO size this as needed
    static size_t tempBufSize;
    static unsigned char responseKeyNT[16];
    static unsigned char ntProofStr[16];
    static unsigned char sessionBaseKey[16];
    static unsigned char encryptedRandomSessionKey[16];
    unsigned char *payloadPtr;
    
    // Nonce used for session key generation
    // TODO generate a random number for this
    static unsigned char exportedSessionKey[16] = 
        {13,123,123,4,3,242,234,23,123,13,31,45,34,143,234,171};
    
    struct hmac_md5_context hmac_md5_context;
    struct rc4_context rc4_context;
    
    
    // Check that this is a valid challenge message
    if (challengeSize < sizeof(NTLM_CHALLENGE_MESSAGE))
        return 0;
    if (memcmp(challengeMsg->Signature, "NTLMSSP", 8) != 0)
        return 0;
    if (challengeMsg->MessageType != NtLmChallenge)
        return 0;
    // TODO verify flags

    /* Compute NT one-way function v2 */
    NTOWFv2(passwordSize, password, userSize, userUpperCase,
        userDomainSize, userDomain, responseKeyNT);

    // TODO special case for anonymous logins

    /* Construct temp buffer used to compute NTProofStr */
    memset(tempBuf, 0, sizeof(tempBuf));
    tempBuf[0] = 1; // Responseversion
    tempBuf[1] = 1; // HiResponseversion
    
    // timestamp (taken from challenge message)
    // TODO handle case where it's not provided in challenge?
    infoPtr = NTLM_GetTargetInfo(challengeMsg, challengeSize, MsvAvTimestamp,
        &infoSize);
    if (infoPtr && infoSize == 8)
        memcpy(tempBuf+8, infoPtr, 8);
    
    // client challenge
    // TODO Generate random ClientChallenge
    static uint64_t clientChallenge = 0x5e4cabd35234cd45;
    memcpy(tempBuf+16, &clientChallenge, 8);

    payloadPtr = tempBuf + 28;

    if (infoPtr != NULL) {
        if (NTLM_GetTargetInfo(challengeMsg, challengeSize, MsvAvFlags,
            &infoSize) == NULL) {
            ((AV_PAIR*)payloadPtr)->AvId = MsvAvFlags;
            ((AV_PAIR*)payloadPtr)->AvLen = 4;
            payloadPtr += 4;
            *(uint32_t*)payloadPtr = 0x00000002; // auth message includes MIC
            payloadPtr += 4;
        } else {
            // TODO should update existing flags.
        }
    }

    // TODO Validate that locations specified are within input buffer
    //      and do not overflow output buffer
    // TODO Adjust target info as specified in [MS-NLMP] (end of sec. 3.1.5.1.2)
    memcpy(payloadPtr, (const unsigned char *)challengeMsg
        + challengeMsg->TargetInfoFields.BufferOffset,
        challengeMsg->TargetInfoFields.Len);
    payloadPtr += challengeMsg->TargetInfoFields.Len;

    tempBufSize = payloadPtr - tempBuf + 4;

    /* Compute NTProofStr */
    hmac_md5_init(&hmac_md5_context, responseKeyNT, sizeof(responseKeyNT));
    hmac_md5_update(&hmac_md5_context, (void*)&challengeMsg->ServerChallenge,
        sizeof(challengeMsg->ServerChallenge));
    hmac_md5_update(&hmac_md5_context, tempBuf, tempBufSize);
    hmac_md5_finalize(&hmac_md5_context);
    memcpy(ntProofStr, hmac_md5_context.u[0].ctx.hash, 16);

    /* Compute SessionBaseKey (which is used as KeyExchangeKey) */
    hmac_md5_init(&hmac_md5_context, responseKeyNT, sizeof(responseKeyNT));
    hmac_md5_compute(&hmac_md5_context, ntProofStr, sizeof(ntProofStr));
    memcpy(sessionBaseKey, hmac_md5_context.u[0].ctx.hash, 16);

    /* Compute EncryptedRandomSessionKey */
    rc4_init(&rc4_context, sessionBaseKey, sizeof(sessionBaseKey));
    rc4_process(&rc4_context, exportedSessionKey, encryptedRandomSessionKey,
        16);

    /* Generate NTLM authenticate message */

    memset(&authMsg, 0, sizeof(NTLM_AUTHENTICATE_MESSAGE));
    memcpy(authMsg.Signature, "NTLMSSP", 8);
    authMsg.MessageType = NtLmAuthenticate;
    
    payloadPtr = authMsg.Payload;
    
    // Send 24 zero bytes as LmChallengeResponse
    authMsg.LmChallengeResponseFields.Len =
        authMsg.LmChallengeResponseFields.MaxLen = 24;
    authMsg.LmChallengeResponseFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    payloadPtr += 24;

    authMsg.NtChallengeResponseFields.Len =
        authMsg.NtChallengeResponseFields.MaxLen = 
        sizeof(ntProofStr) + tempBufSize;
    authMsg.NtChallengeResponseFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, ntProofStr, sizeof(ntProofStr));
    payloadPtr += sizeof(ntProofStr);
    memcpy(payloadPtr, tempBuf, tempBufSize);
    payloadPtr += tempBufSize;

    authMsg.DomainNameFields.Len =
        authMsg.DomainNameFields.MaxLen = userDomainSize;
    authMsg.DomainNameFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, userDomain, userDomainSize);
    payloadPtr += userDomainSize;
    
    authMsg.UserNameFields.Len =
        authMsg.UserNameFields.MaxLen = userSize;
    authMsg.UserNameFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, user, userSize);
    payloadPtr += userSize;
    
    // workstation name = "IIGS"
    // TODO generate a more unique one, or allow it to be configured
    authMsg.WorkstationNameFields.Len =
        authMsg.WorkstationNameFields.MaxLen = 8;
    authMsg.WorkstationNameFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, u"IIGS", 8);
    payloadPtr += 8;
    
    authMsg.EncryptedRandomSessionKeyFields.Len =
        authMsg.EncryptedRandomSessionKeyFields.MaxLen = 16;
    authMsg.EncryptedRandomSessionKeyFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, encryptedRandomSessionKey, 16);
    payloadPtr += 16;
    
    //authMsg.NegotiateFlags = challengeMsg->NegotiateFlags;
    authMsg.NegotiateFlags =
            NTLMSSP_NEGOTIATE_KEY_EXCH +
            NTLMSSP_NEGOTIATE_128 +
            //NTLMSSP_NEGOTIATE_TARGET_INFO +
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY +
            //NTLMSSP_NEGOTIATE_ALWAYS_SIGN +
            NTLMSSP_NEGOTIATE_NTLM +
            //NTLMSSP_NEGOTIATE_SIGN +
            //NTLMSSP_REQUEST_TARGET +
            NTLMSSP_NEGOTIATE_UNICODE,
    // TODO adjust flags?
    
    // TODO choose what version to send, if any
    authMsg.Version.ProductMajorVersion = 6;
    authMsg.Version.ProductBuild = 1;
    authMsg.Version.NTLMRevisionCurrent = NTLMSSP_REVISION_W2K3;

    *resultSize = payloadPtr - (unsigned char*)&authMsg;

    // set authMsg.MIC
    hmac_md5_init(&hmac_md5_context, exportedSessionKey,
        sizeof(exportedSessionKey));
    hmac_md5_update(&hmac_md5_context, (const void *)&negotiateMessage,
        sizeof(negotiateMessage));
    hmac_md5_update(&hmac_md5_context, (const void *)challengeMsg,
        challengeSize);
    hmac_md5_update(&hmac_md5_context, (const void *)&authMsg, *resultSize);
    hmac_md5_finalize(&hmac_md5_context);
    memcpy(authMsg.MIC, hmac_md5_context.u[0].ctx.hash, 16);

    return (unsigned char *)&authMsg;
}

#ifdef NTLM_TEST
#include <stdio.h>

uint16_t user[4] = u"USER";
uint16_t userDom[6] = u"Domain";
uint16_t password[8] = u"Password";

int main(void) {
    static unsigned char responseKeyNT[16];

    NTOWFv2(sizeof(password), password, sizeof(user), user,
        sizeof(userDom), userDom, responseKeyNT);

    printf("NTOWFv2 = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", responseKeyNT[i]);
    }
    printf("\n");
}
#endif
