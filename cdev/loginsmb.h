#ifndef LOGINSMB_H
#define LOGINSMB_H

#include <types.h>

unsigned LoginToSMBServer(char *username, char *password, char *domain,
        LongWord connectionID, LongWord *sessionID);

#endif
