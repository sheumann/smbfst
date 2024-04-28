#ifndef NTLM_H
#define NTLM_H

#include <stdbool.h>
#include "auth/auth.h"
#include "auth/ntlmproto.h"
#include "fst/fstspecific.h"

typedef struct {
    unsigned char signkey[16];
    unsigned char sealkey[16];
} NTLM_Context;


void NTLM_GetNegotiateMessage(NTLM_Context *ctx, unsigned char *buf);

bool GetNTLMv2Hash(uint16_t passwordSize, char16_t password[],
                   uint16_t userNameSize, char16_t userName[],
                   uint16_t userDomainSize, char16_t userDomain[],
                   unsigned  char result[16]);

unsigned char *NTLM_HandleChallenge(NTLM_Context *ctx, AuthInfo *authInfo,
                                    const NTLM_CHALLENGE_MESSAGE *challengeMsg,
                                    uint16_t challengeSize, size_t *resultSize,
                                    uint8_t sessionKey[16]);

unsigned char *NTLM_GetMechListMIC(NTLM_Context *ctx,
                                   const unsigned char *mechList,
                                   uint16_t mechListSize, size_t *resultSize);

#endif
