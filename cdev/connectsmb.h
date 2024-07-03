#ifndef CONNECTSMB_H
#define CONNECTSMB_H

#include <types.h>

unsigned ConnectToSMBServer(char *host, char *port, LongWord ipAddress,
    LongWord *connectionID);

#endif
