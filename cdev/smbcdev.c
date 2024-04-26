#define GENERATE_ROOT
#include "defs.h"
#include <types.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <locator.h>
#include <misctool.h>
#include <gsos.h>
#include <orca.h>
#include <quickdraw.h>
#include <window.h>
#include <control.h>
#include <resources.h>
#include <stdfile.h>
#include <lineedit.h>
#include <memory.h>
#include <desk.h>
#include <menu.h>
#include <finder.h>
#include <tcpip.h>
#include "cdev/addressparser.h"
#include "fst/fstspecific.h"
#include "cdev/connectsmb.h"
#include "cdev/loginsmb.h"
#include "cdev/mountsmbvol.h"
#include "cdev/errorcodes.h"

#pragma cdev CDEVMain

#define MachineCDEV     1
#define BootCDEV        2
#define InitCDEV        4
#define CloseCDEV       5
#define EventsCDEV      6
#define CreateCDEV      7
#define AboutCDEV       8
#define RectCDEV        9
#define HitCDEV         10
#define RunCDEV         11
#define EditCDEV        12

#define cdevWindow          1000

#define serverAddressTxt    2
#define addressLine         3
#define connectBtn          1

FSTInfoRecGS fstInfoRec;

char addressBuf[257];

WindowPtr wPtr = NULL;

Word modifiers = 0;

void DisplayError(unsigned errorCode) {
        AlertWindow(awResource+awButtonLayout, NULL, errorCode);
}

static void ReleaseConnection(LongWord connectionID) {
    static SMBConnectionRec connectionRec = {
        .pCount = 3,
        .fileSysID = smbFSID,
        .commandNum = SMB_CONNECTION_RELEASE,
    };

    connectionRec.connectionID = connectionID;
    FSTSpecific(&connectionRec);
}

static void ReleaseSession(LongWord sessionID) {
    static SMBSessionRec sessionRec = {
        .pCount = 3,
        .fileSysID = smbFSID,
        .commandNum = SMB_SESSION_RELEASE,
    };

    sessionRec.sessionID = sessionID;
    FSTSpecific(&sessionRec);
}


Boolean CheckVersions(void)
{
    /* Check for Marinetti (SMB FST will keep it active if installed) */
    if (!TCPIPStatus() || toolerror())
        return FALSE;
    
    return TRUE;
}

void DoConnect(void)
{
    AddressParts addressParts;
    CtlRecHndl ctl;
    unsigned errorCode;
    LongWord connectionID;
    LongWord sessionID;

    GetLETextByID(wPtr, addressLine, (StringPtr)&addressBuf);
    if (addressBuf[0] == 0) {
        DisplayError(noServerNameError);
        goto fixcaret;
    }
    
    addressParts = ParseAddress(addressBuf+1);
    if (addressParts.errorFound) {
        DisplayError(invalidAddressError);
        goto fixcaret;
    }

    if (!CheckVersions()) {
        DisplayError(fstMissingError);
        goto fixcaret;
    }

    errorCode =
        ConnectToSMBServer(addressParts.host, addressParts.port, &connectionID);
    if (errorCode) {
        DisplayError(errorCode);
        goto fixcaret;
    }
    
    errorCode = LoginToSMBServer(addressParts.username, addressParts.password,
        addressParts.domain, connectionID, &sessionID);
    if (errorCode) {
        ReleaseConnection(connectionID);
        DisplayError(errorCode);
        goto fixcaret;
    }
    ReleaseConnection(connectionID);

    errorCode = MountSMBVolumes(addressParts.share, sessionID);
    if (errorCode) {
        ReleaseSession(sessionID);
        DisplayError(errorCode);
        goto fixcaret;
    }
    ReleaseSession(sessionID);

fixcaret:
    /* Work around issue where parts of the LE caret may flash out of sync */
    ctl = GetCtlHandleFromID(wPtr, addressLine);
    LEDeactivate((LERecHndl) GetCtlTitle(ctl));
    if (FindTargetCtl() == ctl) {
        LEActivate((LERecHndl) GetCtlTitle(ctl));
    }
}

void DoHit(long ctlID, CtlRecHndl ctlHandle)
{
    if (!wPtr)  /* shouldn't happen */
        return;

    if (ctlID == connectBtn) {
        DoConnect();
    }
    
    return;
}

long DoMachine(void)
{
    unsigned int i;

    /* Check for presence of SMB FST. */
    fstInfoRec.pCount = 2;
    fstInfoRec.fileSysID = 0;
    for (i = 1; fstInfoRec.fileSysID != smbFSID; i++) {
        fstInfoRec.fstNum = i;
        GetFSTInfoGS(&fstInfoRec);
        if (toolerror() == paramRangeErr) {
            InitCursor();
            DisplayError(fstMissingError);
            return 0;
        }
    }
    
    return 1;
}

void DoEdit(Word op)
{
    CtlRecHndl ctl;
    GrafPortPtr port;
    
    if (!wPtr)
        return;
    port = GetPort();
    SetPort(wPtr);
    
    ctl = FindTargetCtl();
    if (toolerror() || GetCtlID(ctl) != addressLine)
        goto ret;

    switch (op) {
    case cutAction:     LECut((LERecHndl) GetCtlTitle(ctl));
                        if (LEGetScrapLen() > 0)
                            LEToScrap();
                        break;
    case copyAction:    LECopy((LERecHndl) GetCtlTitle(ctl));
                        if (LEGetScrapLen() > 0)
                            LEToScrap();
                        break;
    case pasteAction:   LEFromScrap();
                        LEPaste((LERecHndl) GetCtlTitle(ctl));
                        break;
    case clearAction:   LEDelete((LERecHndl) GetCtlTitle(ctl));
                        break;
    }

ret:
    SetPort(port);
}

void DoCreate(WindowPtr windPtr)
{
    wPtr = windPtr;
    NewControl2(wPtr, resourceToResource, cdevWindow);
}

LongWord CDEVMain (LongWord data2, LongWord data1, Word message)
{
    long result = 0;

    switch(message) {
    case MachineCDEV:   result = DoMachine();               break;
    case HitCDEV:       DoHit(data2, (CtlRecHndl)data1);    break;
    case EditCDEV:      DoEdit(data1 & 0xFFFF);             break;
    case CreateCDEV:    DoCreate((WindowPtr)data1);         break;
    case CloseCDEV:     wPtr = NULL;                        break;
    case EventsCDEV:    modifiers = ((EventRecordPtr)data1)->modifiers;
                        break;
    }

    return result;
}
