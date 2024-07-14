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

#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include "fst/fstspecific.h"

/* This size must be sufficient to hold any mechList we may produce. */
#define MAX_MECHLIST_SIZE 100

typedef struct {
    char16_t *userName;
    Word userNameSize;
    char16_t *userDomain;
    Word userDomainSize;
    unsigned char ntlmv2Hash[16];
    bool anonymous;
} AuthInfo;

typedef struct {
    unsigned step;
    unsigned char *negotiateMessage;
    unsigned char *challengeMessage;
    unsigned char *authenticateMessage;

    uint8_t mechList[MAX_MECHLIST_SIZE];
    uint16_t mechListSize;
    
    uint8_t signKey[16];
    
    AuthInfo *authInfo;
} AuthState;

void InitAuth(AuthState *state, AuthInfo *authInfo);

size_t DoAuthStep(AuthState *state,
                  const unsigned char *previousMsg, uint16_t previousSize,
                  unsigned char *msgBuf, uint16_t msgBufSize);

#endif
