#ifndef LOGINSMB_H
#define LOGINSMB_H

#include <types.h>
#include "cdev/addressparser.h"

unsigned LoginToSMBServer(AddressParts *address, LongWord connectionID,
    LongWord *sessionID);

#endif
