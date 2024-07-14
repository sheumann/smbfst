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
