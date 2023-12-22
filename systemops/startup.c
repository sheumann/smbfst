#include "defs.h"

#include <misctool.h>
#include <orca.h>
#include <stddef.h>
#include "fstdata.h"
#include "driver.h"

extern pascal void SystemUserID (unsigned, char *);

#define GET_SYS_GBUF 0x01fc3c
#define INSTALL_DRIVER 0x01fca8

/*
 * Called when GS/OS starts up, either on boot or when switching back from P8.
 */
int Startup(void) {
    int result;

    SystemUserID(GetNewID(0x3300), NULL);

    InitDIBs();

    asm {
        phd
        lda gsosDP
        tcd

        jsl GET_SYS_GBUF
        stx gbuf
        sty gbuf+2

        ldx #dibList
        ldy #^dibList
        jsl INSTALL_DRIVER

        pld
        sta result
    }

    return result;
}
