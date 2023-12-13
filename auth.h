#include <stdint.h>

/* This size must be sufficient to hold any mechList we may produce. */
#define MAX_MECHLIST_SIZE 100

typedef struct {
    unsigned step;
    unsigned char *negotiateMessage;
    unsigned char *challengeMessage;
    unsigned char *authenticateMessage;

    uint8_t mechList[MAX_MECHLIST_SIZE];
    uint16_t mechListSize;
    
    uint8_t signKey[16];
} AuthState;

void InitAuth(AuthState *state);

size_t DoAuthStep(AuthState *state, const unsigned char *previousMsg,
                  uint16_t previousSize, unsigned char *msgBuf);
