#include "defs.h"

#include <misctool.h>
#include <orca.h>
#include <stddef.h>

extern pascal void SystemUserID (unsigned, char *);

/*
 * Called when GS/OS starts up, either on boot or when switching back from P8.
 */
int Startup(void) {
    SystemUserID(GetNewID(0x3300), NULL);


    return 0;
}
