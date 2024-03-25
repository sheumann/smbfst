#include <stddef.h>
#include <string.h>
#include <uchar.h>

#include <ctype.h>
#include <stdlib.h>

#include "defs.h"
#include "crypto/md4.h"
#include "crypto/md5.h"
#include "crypto/rc4.h"

#include "ntlm.h"
#include "authinfo.h"
#include "auth.h"
#include "gsosdata.h"
#include "alloc.h"

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

typedef struct {
    union {
        struct md4_context md4_context;
        struct md5_context md5_context;
        struct rc4_context rc4_context;
    };
    struct hmac_md5_context hmac_md5_context;
} ctxRec;
_Static_assert(sizeof(ctxRec) <= GBUF_SIZE, "");

#define c (*(ctxRec*)gbuf)

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
    md4_init(&c.md4_context);
    md4_update(&c.md4_context, (const void*)password, passwordSize);
    md4_finalize(&c.md4_context);
    
    hmac_md5_init(&c.hmac_md5_context,
        c.md4_context.hash, sizeof(c.md4_context.hash));
    hmac_md5_update(&c.hmac_md5_context, (const void*)userUpperCase, userSize);
    hmac_md5_update(&c.hmac_md5_context, (const void*)userDomain, userDomainSize);
    hmac_md5_finalize(&c.hmac_md5_context);
    
    memcpy(result, c.hmac_md5_context.u[0].ctx.hash, 16);
}

void NTLM_GetNegotiateMessage(NTLM_Context *ctx, unsigned char *buf) {

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
    static uint32_t offset;
    
    offset = challengeMsg->TargetInfoFields.BufferOffset;
    
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

static void GetSignKey(const uint8_t exportedSessionKey[16],
                       uint8_t signKey[16]) {
    static const unsigned char clientString[] =
        "session key to client-to-server signing key magic constant";
    
    md5_init(&c.md5_context);
    md5_update(&c.md5_context, exportedSessionKey, 16);
    md5_update(&c.md5_context, clientString, sizeof(clientString));
    md5_finalize(&c.md5_context);
    memcpy(signKey, c.md5_context.hash, 16);
}

static void GetSealKey(const uint8_t exportedSessionKey[16],
                       uint8_t sealKey[16]) {
    static const unsigned char clientString[] =
        "session key to client-to-server sealing key magic constant";
    
    md5_init(&c.md5_context);
    md5_update(&c.md5_context, exportedSessionKey, 16); // assumes 128-bit security
    md5_update(&c.md5_context, clientString, sizeof(clientString));
    md5_finalize(&c.md5_context);
    memcpy(sealKey, c.md5_context.hash, 16);
}

unsigned char *NTLM_HandleChallenge(NTLM_Context *ctx,
    SMBAuthenticateRec *authRec,
    const NTLM_CHALLENGE_MESSAGE *challengeMsg, uint16_t challengeSize,
    size_t *resultSize, uint8_t sessionKey[16]) {

    uint16_t infoSize;
    const void *infoPtr;
    static uint8_t tempBuf[8+8+8+4+1000]; // TODO size this as needed
    static size_t tempBufSize;
    static unsigned char responseKeyNT[16];
    static unsigned char ntProofStr[16];
    static unsigned char sessionBaseKey[16];
    static unsigned char encryptedRandomSessionKey[16];
    unsigned char *payloadPtr;
    char16_t *userNameUpperCase;
    unsigned i;
    
    // Nonce used for session key generation
    // TODO generate a random number for this
    static unsigned char exportedSessionKey[16] = 
        {13,123,123,4,3,242,234,23,123,13,31,45,34,143,234,171};
    
    
    // Check that this is a valid challenge message
    if (challengeSize < sizeof(NTLM_CHALLENGE_MESSAGE))
        return 0;
    if (memcmp(challengeMsg->Signature, "NTLMSSP", 8) != 0)
        return 0;
    if (challengeMsg->MessageType != NtLmChallenge)
        return 0;
    // TODO verify flags

    userNameUpperCase = smb_malloc(authRec->userNameSize);
    if (!userNameUpperCase)
        return 0;

    for (i = 0; i < authRec->userNameSize; i++) {
        // TODO properly uppercase non-ASCII characters
        userNameUpperCase[i] = toupper(authRec->userName[i]);
    }

    /* Compute NT one-way function v2 */
    NTOWFv2(authRec->passwordSize, authRec->password,
        authRec->userNameSize, userNameUpperCase,
        authRec->userDomainSize, authRec->userDomain,
        responseKeyNT);

    smb_free(userNameUpperCase);

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
    hmac_md5_init(&c.hmac_md5_context, responseKeyNT, sizeof(responseKeyNT));
    hmac_md5_update(&c.hmac_md5_context, (void*)&challengeMsg->ServerChallenge,
        sizeof(challengeMsg->ServerChallenge));
    hmac_md5_update(&c.hmac_md5_context, tempBuf, tempBufSize);
    hmac_md5_finalize(&c.hmac_md5_context);
    memcpy(ntProofStr, c.hmac_md5_context.u[0].ctx.hash, 16);

    /* Compute SessionBaseKey (which is used as KeyExchangeKey) */
    hmac_md5_init(&c.hmac_md5_context, responseKeyNT, sizeof(responseKeyNT));
    hmac_md5_compute(&c.hmac_md5_context, ntProofStr, sizeof(ntProofStr));
    memcpy(sessionBaseKey, c.hmac_md5_context.u[0].ctx.hash, 16);

    /* Compute EncryptedRandomSessionKey */
    rc4_init(&c.rc4_context, sessionBaseKey, sizeof(sessionBaseKey));
    rc4_process(&c.rc4_context, exportedSessionKey, encryptedRandomSessionKey,
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
        authMsg.DomainNameFields.MaxLen = authRec->userDomainSize;
    authMsg.DomainNameFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, authRec->userDomain, authRec->userDomainSize);
    payloadPtr += authRec->userDomainSize;
    
    authMsg.UserNameFields.Len =
        authMsg.UserNameFields.MaxLen = authRec->userNameSize;
    authMsg.UserNameFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, authRec->userName, authRec->userNameSize);
    payloadPtr += authRec->userNameSize;
    
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
            NTLMSSP_NEGOTIATE_TARGET_INFO +
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY +
            NTLMSSP_NEGOTIATE_ALWAYS_SIGN +
            NTLMSSP_NEGOTIATE_NTLM +
            NTLMSSP_NEGOTIATE_SIGN +
            NTLMSSP_REQUEST_TARGET +
            NTLMSSP_NEGOTIATE_UNICODE,
    // TODO adjust flags?
    
    // TODO choose what version to send, if any
    authMsg.Version.ProductMajorVersion = 6;
    authMsg.Version.ProductBuild = 1;
    authMsg.Version.NTLMRevisionCurrent = NTLMSSP_REVISION_W2K3;

    *resultSize = payloadPtr - (unsigned char*)&authMsg;

    // set authMsg.MIC
    hmac_md5_init(&c.hmac_md5_context, exportedSessionKey,
        sizeof(exportedSessionKey));
    hmac_md5_update(&c.hmac_md5_context, (const void *)&negotiateMessage,
        sizeof(negotiateMessage));
    hmac_md5_update(&c.hmac_md5_context, (const void *)challengeMsg,
        challengeSize);
    hmac_md5_update(&c.hmac_md5_context, (const void *)&authMsg, *resultSize);
    hmac_md5_finalize(&c.hmac_md5_context);
    memcpy(authMsg.MIC, c.hmac_md5_context.u[0].ctx.hash, 16);

    GetSignKey(exportedSessionKey, ctx->signkey);
    GetSealKey(exportedSessionKey, ctx->sealkey);
    
    // save session key for use by SMB
    memcpy(sessionKey, exportedSessionKey, 16);

    return (unsigned char *)&authMsg;
}

unsigned char *NTLM_GetMechListMIC(NTLM_Context *ctx,
    const unsigned char *mechList, uint16_t mechListSize, size_t *resultSize) {

    static NTLMSSP_MESSAGE_SIGNATURE_Extended sig = {
        .Version = 1,
        .SeqNum = 0,
    };

    hmac_md5_init(&c.hmac_md5_context, ctx->signkey, sizeof(ctx->signkey));
    hmac_md5_update(&c.hmac_md5_context, (void*)&sig.SeqNum, sizeof(sig.SeqNum));
    hmac_md5_update(&c.hmac_md5_context, mechList, mechListSize);
    hmac_md5_finalize(&c.hmac_md5_context);

    rc4_init(&c.rc4_context, ctx->sealkey, sizeof(ctx->sealkey));
    rc4_process(&c.rc4_context, c.hmac_md5_context.u[0].ctx.hash,
        (void*)&sig.Checksum, 8);

    *resultSize = sizeof(sig);

    return (unsigned char *)&sig;
}


#ifdef NTLM_TEST
#include <stdio.h>

int main(void) {
    static unsigned char responseKeyNT[16];
    
    uint16_t user[4] = u"USER";
    uint16_t userDom[6] = u"Domain";
    uint16_t password[8] = u"Password";

    NTOWFv2(sizeof(password), password, sizeof(user), user,
        sizeof(userDom), userDom, responseKeyNT);

    printf("NTOWFv2 = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", responseKeyNT[i]);
    }
    printf("\n");
    
    uint8_t randomSessionKey[16] = "UUUUUUUUUUUUUUUU";
    NTLM_Context ctx;
    
    GetSignKey(randomSessionKey, ctx.signkey);
    GetSealKey(randomSessionKey, ctx.sealkey);
    
    printf("signkey = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ctx.signkey[i]);
    }
    printf("\n");

    printf("sealkey = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ctx.sealkey[i]);
    }
    printf("\n");
    
    uint16_t message[9] = u"Plaintext";
    
    size_t sigSize;
    unsigned char *sig =
        NTLM_GetMechListMIC(&ctx, (void*)message, sizeof(message), &sigSize);
    
    printf("signature = ");
    for (int i = 0; i < sigSize; i++) {
        printf("%02x ", sig[i]);
    }
    printf("\n");
}
#endif
