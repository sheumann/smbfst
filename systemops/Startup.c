#include "defs.h"

#include <misctool.h>
#include <orca.h>
#include <stddef.h>
#include <locator.h>
#include <gsos.h>
#include "gsos/gsosdata.h"
#include "driver/driver.h"
#include "systemops/Startup.h"
#include "utils/random.h"
#include "smb2/smb2.h"

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

/*
 * This vector is called when switching to/from P8 or shutting down.
 * It passes an argument in A.
 */
#define p8SwitchVector (*(LongWord*)0xe100b4)

/*
 * Indicates whether we are doing warm (i.e. switch to/from P8) or cold 
 * startup/shutdown.
 */
#define warm_cold_flag (*(Word*)0xe101d0)

static LongWord oldPriorityVector;
static LongWord oldP8SwitchVector;

enum MarinettiStatus marinettiStatus = tcpipUnloaded;

static asm void PriorityHandler(void);
static asm void P8SwitchHandler(void);

static void Startup2(void);
static void HandleOSP8Switch(int a);
static void NotificationProc(void);
static asm unsigned InstallDIBs(void);

static struct {
    Long reserved1;
    Word reserved2;
    Word Signature;
    Long Event_flags;
    Long Event_code;
    Byte jml;
    void (*proc)(void);
} notificationProcRec;

#define NOTIFY_GSOS_SWITCH 0x04

/*
 * Called when GS/OS starts up on boot (not when switching back from P8).
 */
int Startup(void) {
    int result;

    SystemUserID(GetNewID(0x3300), NULL);

    InitDIBs();
    result = InstallDIBs();
    
    if (result == 0) {
        oldPriorityVector = priorityVector;
        priorityVector = JML | ((uintptr_t)PriorityHandler << 8);
        
        oldP8SwitchVector = p8SwitchVector;
        p8SwitchVector = JML | ((uintptr_t)P8SwitchHandler << 8);

        InitRandom();
    }

    return result;
}

/*
 * Install out DIBs.  Returns error code from INSTALL_DRIVER, if any.
 */
static asm unsigned InstallDIBs(void) {
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
    rtl
}

static asm void PriorityHandler(void) {
    jsl >Startup2
    jml >oldPriorityVector
}

/*
 * This is the second-phase startup code, which is run from the priority vector.
 * It runs after tool patches and inits are loaded, but before desk accessories.
 */
#pragma databank 1
static void Startup2(void) {
    NotifyProcRecGS addNotifyProcRec;

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
        
        InitSMB();

        notificationProcRec.Signature = 0xA55A;
        notificationProcRec.Event_flags = NOTIFY_GSOS_SWITCH;
        notificationProcRec.jml = JML;
        notificationProcRec.proc = NotificationProc;
        addNotifyProcRec.pCount = 1;
        addNotifyProcRec.procPointer = (ProcPtr)&notificationProcRec;
        AddNotifyProcGS(&addNotifyProcRec);
    }
}
#pragma databank 0

static asm void P8SwitchHandler(void) {
    pha
    pha
    jsl >HandleOSP8Switch
    pla
    jml >oldP8SwitchVector
}

/*
 * This is called at shutdown time or when switching to/from GS/OS.
 *
 * A=1 indicates quitting GS/OS, either to shut down or switch to P8.
 */
#pragma databank 1
static void HandleOSP8Switch(int a) {
    unsigned i;

    /*
     * If system is shutting down, unmount all SMB volumes.
     */
    if (a == 1 && warm_cold_flag == 0) {
        for (i = 0; i < NDIBS; i++) {
            UnmountSMBVolume(&dibs[i]);
        }
    }
}
#pragma databank 0

/*
 * Notification procedure called when switching to GS/OS.
 */
#pragma databank 1
static void NotificationProc(void) {
    bool oom;
    VirtualPointer vcrVP;
    VCR *vcr;
    GSString *volName;
    unsigned i;

    /*
     * Re-install DIBs and VCRs for SMB volumes on switch from P8 to GS/OS.
     */
    if (notificationProcRec.Event_code & NOTIFY_GSOS_SWITCH) {
        if (InstallDIBs() == 0) {
            for (i = 0; i < NDIBS; i++) {
                if (dibs[i].extendedDIBPtr != NULL) {
                    volName = dibs[i].volName;
                    asm {
                        stz oom
                        ldx volName
                        ldy volName+2
                        phd
                        lda gsosDP
                        tcd
                        lda #sizeof(VCR)
                        jsl ALLOC_VCR
                        pld
                        stx vcrVP
                        sty vcrVP+2
                        rol oom
                    }
                    
                    if (!oom) {
                        dibs[i].vcrVP = vcrVP;
        
                        DerefVP(vcr, vcrVP);
            
                        vcr->status = 0;
                        vcr->openCount = 0;
                        vcr->fstID = smbFSID;
                        vcr->devNum = dibs[i].DIBDevNum;
                    } else {
                        UnmountSMBVolume(&dibs[i]);
                    }
                }
            }
        }
    }
}
#pragma databank 0
