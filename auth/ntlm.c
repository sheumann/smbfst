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

#include <stddef.h>
#include <string.h>
#include <uchar.h>

#include <stdlib.h>
#include <intmath.h>

#include "defs.h"
#include "crypto/md4.h"
#include "crypto/md5.h"
#include "crypto/rc4.h"

#include "auth/ntlm.h"
#include "auth/auth.h"
#include "gsos/gsosdata.h"
#include "utils/alloc.h"
#include "utils/random.h"
#include "utils/charsetutils.h"
#include "smb2/smb2.h"

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

static char16_t workstationName[13] = u"IIGS-00000000";
static bool workstationNameInitialized = false;

#define LM_CHALLENGE_RESPONSE_SIZE 24

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

static void InitWorkstationName(void) {
    static char num[8] = "00000000";
    unsigned i;
    
    Long2Hex(clientGUID.time_low, num, sizeof(num));
    for (i = 0; i < sizeof(num); i++) {
        workstationName[i+5] = num[i];
    }
    
    workstationNameInitialized = true;
}

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

bool GetNTLMv2Hash(uint16_t passwordSize, char16_t password[],
                   uint16_t userNameSize, char16_t userName[],
                   uint16_t userDomainSize, char16_t userDomain[],
                   unsigned  char result[16]) {
    char16_t *userNameUpperCase;

    userNameUpperCase = smb_malloc(userNameSize);
    if (!userNameUpperCase && userNameSize != 0)
        return false;

    UTF16ToUpper(userNameUpperCase, userName, userNameSize / 2);

    /* Compute NT one-way function v2 */
    NTOWFv2(passwordSize, password,
        userNameSize, userNameUpperCase,
        userDomainSize, userDomain,
        result);

    smb_free(userNameUpperCase);

    return true;
}

void NTLM_GetNegotiateMessage(NTLM_Context *ctx, unsigned char *buf) {

    memcpy(buf, &negotiateMessage, sizeof(negotiateMessage));
}

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

/*
 * This handles an NTLMv2 challenge message and returns a pointer to the
 * authenticate message generated in response (or NULL in case of an error).
 *
 * The pointer is allocated with smb_malloc and must be freed by the caller.
 * The authenticate message is always at least 256 bytes long; this is not
 * required by the NTLM spec, but we pad the message if necessary to ensure
 * this, because it is convenient for our SMB2 authentication implementation.
 */
unsigned char *NTLM_HandleChallenge(NTLM_Context *ctx, AuthInfo *authInfo,
    const NTLM_CHALLENGE_MESSAGE *challengeMsg, uint16_t challengeSize,
    size_t *resultSize, uint8_t sessionKey[16]) {

    uint16_t infoSize;
    const void *infoPtr;
    uint8_t *tempBuf;
    static size_t tempBufSize;
    static unsigned char ntProofStr[16];
    static unsigned char sessionBaseKey[16];
    static unsigned char encryptedRandomSessionKey[16];
    unsigned char *ntlmResponseBuf;
    unsigned char *payloadPtr;
    unsigned char *randPtr;
    
    // Nonce used for session key generation
    static unsigned char exportedSessionKey[16];

    static uint64_t clientChallenge;
    
    // Check that this is a valid challenge message
    if (challengeSize < sizeof(NTLM_CHALLENGE_MESSAGE))
        return NULL;
    if (memcmp(challengeMsg->Signature, "NTLMSSP", 8) != 0)
        return NULL;
    if (challengeMsg->MessageType != NtLmChallenge)
        return NULL;
    if ((uint64_t)challengeMsg->TargetInfoFields.BufferOffset
        + challengeMsg->TargetInfoFields.Len > challengeSize)
        return NULL;
    // TODO verify flags

    /* Generate random values for use in NTLM */
    randPtr = GetRandom();
    memcpy(exportedSessionKey, randPtr, 16);
    clientChallenge = *(uint64_t*)(randPtr + 20);

    if (!authInfo->anonymous) {
        /* Construct temp buffer used to compute NTProofStr (see [MS-NLMP] 3.3.2) */
        tempBufSize = 1UL + 1 + 6 + 8 + 8 + 4
            + 8 /* for possible added MsvAvFlags */
            + challengeMsg->TargetInfoFields.Len + 4;
        tempBuf = smb_malloc(tempBufSize);
        if (tempBuf == NULL)
            return NULL;
    
        memset(tempBuf, 0, tempBufSize);
        tempBuf[0] = 1; // Responseversion
        tempBuf[1] = 1; // HiResponseversion
        
        // timestamp (taken from challenge message)
        // TODO handle case where timestamp is not provided in challenge?
        infoPtr = NTLM_GetTargetInfo(challengeMsg, challengeSize, MsvAvTimestamp,
            &infoSize);
        if (infoPtr && infoSize == 8)
            memcpy(tempBuf+8, infoPtr, 8);
        
        // client challenge
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
    
        // TODO Adjust target info as specified in [MS-NLMP] (end of sec. 3.1.5.1.2)
        memcpy(payloadPtr, (const unsigned char *)challengeMsg
            + challengeMsg->TargetInfoFields.BufferOffset,
            challengeMsg->TargetInfoFields.Len);
        payloadPtr += challengeMsg->TargetInfoFields.Len;
    
        tempBufSize = payloadPtr - tempBuf + 4;

#define responseKeyNT (authInfo->ntlmv2Hash)
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
#undef responseKeyNT
    } else {
        tempBuf = NULL;
        tempBufSize = 0;
        memset(sessionBaseKey, 0, 16);
    }

    /* Compute EncryptedRandomSessionKey */
    rc4_init(&c.rc4_context, sessionBaseKey, sizeof(sessionBaseKey));
    rc4_process(&c.rc4_context, exportedSessionKey, encryptedRandomSessionKey,
        16);

    /* Generate NTLM authenticate message */
    
    if (!authInfo->anonymous) {
        *resultSize = sizeof(NTLM_AUTHENTICATE_MESSAGE)
            + LM_CHALLENGE_RESPONSE_SIZE
            + sizeof(ntProofStr) + tempBufSize
            + authInfo->userDomainSize
            + authInfo->userNameSize
            + sizeof(workstationName)
            + sizeof(encryptedRandomSessionKey);
    } else {
        *resultSize = sizeof(NTLM_AUTHENTICATE_MESSAGE)
            + 2 /* for one-byte LmChallengeResponse and one-byte padding */
            + authInfo->userDomainSize
            + authInfo->userNameSize
            + sizeof(workstationName)
            + sizeof(encryptedRandomSessionKey);    
    }

    // Pad message to be at least 256 bytes.  This is not required by the
    // NTLM spec, but it is convenient for our SMB auth implementation.
    if (*resultSize < 256)
        *resultSize = 256;
    
    ntlmResponseBuf = smb_malloc(*resultSize);
    if (ntlmResponseBuf == NULL) {
        smb_free(tempBuf);
        return NULL;
    }
    memset(ntlmResponseBuf, 0, *resultSize);

#define authMsg (*(NTLM_AUTHENTICATE_MESSAGE*)ntlmResponseBuf)
    memcpy(authMsg.Signature, "NTLMSSP", 8);
    authMsg.MessageType = NtLmAuthenticate;
    
    payloadPtr = authMsg.Payload;
    
    if (!authInfo->anonymous) {
        // Send 24 zero bytes as LmChallengeResponse
        authMsg.LmChallengeResponseFields.Len =
            authMsg.LmChallengeResponseFields.MaxLen =
            LM_CHALLENGE_RESPONSE_SIZE;
        authMsg.LmChallengeResponseFields.BufferOffset =
            payloadPtr - (unsigned char*)&authMsg;
        payloadPtr += LM_CHALLENGE_RESPONSE_SIZE;
        
        // Send ntProofStr plus tempBuf as NtChallengeResponse
        authMsg.NtChallengeResponseFields.Len =
            authMsg.NtChallengeResponseFields.MaxLen = 
            sizeof(ntProofStr) + tempBufSize;
        authMsg.NtChallengeResponseFields.BufferOffset =
            payloadPtr - (unsigned char*)&authMsg;

        memcpy(payloadPtr, ntProofStr, sizeof(ntProofStr));
        payloadPtr += sizeof(ntProofStr);
        memcpy(payloadPtr, tempBuf, tempBufSize);
        payloadPtr += tempBufSize;

        smb_free(tempBuf);
    } else {
        // Send one zero byte as LmChallengeResponse if anonymous
        authMsg.LmChallengeResponseFields.Len =
            authMsg.LmChallengeResponseFields.MaxLen = 1;
        authMsg.LmChallengeResponseFields.BufferOffset =
            payloadPtr - (unsigned char*)&authMsg;
        /*
         * Add an extra byte as padding to keep subsequent strings two-byte
         * aligned.  Wireshark suggests this is required, although I don't
         * see anything in [MS-NLMP] about it.
         */
        payloadPtr += 1 + 1;
        
        // Set NTChallengeResponse fields to 0 if anonymous
        authMsg.NtChallengeResponseFields.Len =
            authMsg.NtChallengeResponseFields.MaxLen = 0;
        authMsg.NtChallengeResponseFields.BufferOffset = 0;
    }

    authMsg.DomainNameFields.Len =
        authMsg.DomainNameFields.MaxLen = authInfo->userDomainSize;
    authMsg.DomainNameFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, authInfo->userDomain, authInfo->userDomainSize);
    payloadPtr += authInfo->userDomainSize;
    
    authMsg.UserNameFields.Len =
        authMsg.UserNameFields.MaxLen = authInfo->userNameSize;
    authMsg.UserNameFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, authInfo->userName, authInfo->userNameSize);
    payloadPtr += authInfo->userNameSize;

    if (!workstationNameInitialized)
        InitWorkstationName();
    authMsg.WorkstationNameFields.Len =
        authMsg.WorkstationNameFields.MaxLen = sizeof(workstationName);
    authMsg.WorkstationNameFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, workstationName, sizeof(workstationName));
    payloadPtr += sizeof(workstationName);
    
    authMsg.EncryptedRandomSessionKeyFields.Len =
        authMsg.EncryptedRandomSessionKeyFields.MaxLen =
        sizeof(encryptedRandomSessionKey);
    authMsg.EncryptedRandomSessionKeyFields.BufferOffset =
        payloadPtr - (unsigned char*)&authMsg;
    memcpy(payloadPtr, encryptedRandomSessionKey,
        sizeof(encryptedRandomSessionKey));
    payloadPtr += sizeof(encryptedRandomSessionKey);

    authMsg.NegotiateFlags =
            NTLMSSP_NEGOTIATE_KEY_EXCH +
            NTLMSSP_NEGOTIATE_128 +
            NTLMSSP_NEGOTIATE_TARGET_INFO +
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY +
            NTLMSSP_NEGOTIATE_ALWAYS_SIGN +
            NTLMSSP_NEGOTIATE_NTLM +
            NTLMSSP_NEGOTIATE_SIGN +
            NTLMSSP_REQUEST_TARGET +
            NTLMSSP_NEGOTIATE_UNICODE;
    if (authInfo->anonymous)
        authMsg.NegotiateFlags |= NTLMSSP_ANONYMOUS;
    // TODO adjust flags?
    
    // TODO choose what version to send, if any
    authMsg.Version.ProductMajorVersion = 6;
    authMsg.Version.ProductBuild = 1;
    authMsg.Version.NTLMRevisionCurrent = NTLMSSP_REVISION_W2K3;

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
#undef authMsg

    GetSignKey(exportedSessionKey, ctx->signkey);
    GetSealKey(exportedSessionKey, ctx->sealkey);
    
    // save session key for use by SMB
    memcpy(sessionKey, exportedSessionKey, 16);

    return ntlmResponseBuf;
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
