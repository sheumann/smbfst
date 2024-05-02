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
