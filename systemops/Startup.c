#include "defs.h"

#include <misctool.h>
#include <orca.h>
#include <stddef.h>
#include <locator.h>
#include "gsosdata.h"
#include "driver.h"
#include "systemops/Startup.h"
#include "utils/random.h"

extern pascal void SystemUserID (unsigned, char *);

#define JML 0x5c

#define GET_SYS_GBUF 0x01fc3c
#define INSTALL_DRIVER 0x01fca8

/*
 * This is the "priority vector," which is called by the startup code after
 * loading tool patches and inits, but before desk accessories.  This is
 * intended for AppleTalk, but we patch into it because this is a suitable
 * time to run some of our startup code.
 */
#define priorityVector (*(LongWord*)0xe1103a)

static LongWord oldPriorityVector;

enum MarinettiStatus marinettiStatus = tcpipUnloaded;

static asm void PriorityHandler(void);
static void LoadTCPTool(void);

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
    
    if (result == 0) {
        oldPriorityVector = priorityVector;
        priorityVector = JML | ((uintptr_t)PriorityHandler << 8);
        
        InitRandom();
    }

    return result;
}

static asm void PriorityHandler(void) {
    jsl >LoadTCPTool
    jml >oldPriorityVector
}

#pragma databank 1
static void LoadTCPTool(void) {
    if (marinettiStatus == tcpipUnloaded) {
        /*
         * Load Marinetti tool stub.
         */
        LoadOneTool(54, 0x0200);
        if (toolerror()) {
            marinettiStatus = tcpipLoadError;
            return;
        }

        /*
         * Put Marinetti in the default TPT so its tool stub won't be unloaded,
         * even if UnloadOneTool is called on it.  Programs may still call
         * TCPIPStartUp and TCPIPShutDown, but those don't actually do
         * anything, so the practical effect is that Marinetti will always
         * be available, provided that its init was loaded.
         */
        SetDefaultTPT();
        
        marinettiStatus = tcpipLoaded;
        
        SeedEntropy();
    }
}
#pragma databank 0
