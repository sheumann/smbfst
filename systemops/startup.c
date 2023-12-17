#include "defs.h"

#include <misctool.h>
#include <orca.h>
#include <stddef.h>
#include "fstdata.h"

extern pascal void SystemUserID (unsigned, char *);

#define GET_SYS_GBUF 0x01fc3c

/*
 * Called when GS/OS starts up, either on boot or when switching back from P8.
 */
int Startup(void) {
    SystemUserID(GetNewID(0x3300), NULL);

    asm {
        jsl GET_SYS_GBUF
        stx gbuf
        sty gbuf+2
    }

    return 0;
}
