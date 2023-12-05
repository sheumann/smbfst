#include "ntlmproto.h"

void NTLM_GetNegotiateMessage(unsigned char *buf);

int NTLM_HandleChallenge(const NTLM_CHALLENGE_MESSAGE *challengeMsg, uint16_t challengeSize);