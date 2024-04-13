#ifndef NTLM_H
#define NTLM_H

#include "ntlmproto.h"
#include "fstspecific.h"

typedef struct {
    unsigned char signkey[16];
    unsigned char sealkey[16];
} NTLM_Context;


void NTLM_GetNegotiateMessage(NTLM_Context *ctx, unsigned char *buf);

unsigned char *NTLM_HandleChallenge(NTLM_Context *ctx,
                                    SMBAuthenticateRec *authRec,
                                    const NTLM_CHALLENGE_MESSAGE *challengeMsg,
                                    uint16_t challengeSize, size_t *resultSize,
                                    uint8_t sessionKey[16]);

unsigned char *NTLM_GetMechListMIC(NTLM_Context *ctx,
                                   const unsigned char *mechList,
                                   uint16_t mechListSize, size_t *resultSize);

#endif
