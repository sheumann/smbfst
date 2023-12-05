#include <stdint.h>

typedef struct {
    unsigned step;
    unsigned char *negotiateMessage;
    unsigned char *challengeMessage;
    unsigned char *authenticateMessage;
} AuthState;

void InitAuth(AuthState *state);

size_t DoAuthStep(AuthState *state, const unsigned char *previousMsg,
                  uint16_t previousSize, unsigned char *msgBuf);
