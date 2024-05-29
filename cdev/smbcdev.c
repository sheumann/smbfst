#define USE_BLANK_SEG
#define GENERATE_ROOT
#include "defs.h"
#include <types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <locator.h>
#include <misctool.h>
#include <gsos.h>
#include <orca.h>
#include <quickdraw.h>
#include <qdaux.h>
#include <window.h>
#include <control.h>
#include <resources.h>
#include <stdfile.h>
#include <lineedit.h>
#include <memory.h>
#include <desk.h>
#include <menu.h>
#include <list.h>
#include <finder.h>
#include <tcpip.h>
#include "cdev/addressparser.h"
#include "fst/fstspecific.h"
#include "cdev/connectsmb.h"
#include "cdev/loginsmb.h"
#include "cdev/mountsmbvol.h"
#include "cdev/errorcodes.h"
#include "cdev/charset.h"
#include "mdns/mdnssd.h"
#include "mdns/mdnsproto.h"

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

#define TAB 0x09

// SortList/SortList2 compareProc value
#define SORT_CASE_INSENSITIVE ((void*)0x00000001)

#define memNever 0x20

#define cdevWindow          1000

#define serverAddressTxt    2
#define addressLine         3
#define connectBtn          1
#define serversLst          4
#define goOnlineTxt         5
#define goOnlineBtn         6

#define GO_ONLINE_OFFSET    (-10000)

#define INITIAL_INTERVAL (1 * 60)  /* ticks */
#define MAX_INTERVAL     (16 * 60) /* ticks */

FSTInfoRecGS fstInfoRec;

char addressBuf[257];

WindowPtr wPtr = NULL;

bool mdnsActive;
Word ipid;
LongWord lastQueryTime;
uint16_t interval;

CtlRecHndl addressLineHndl;
CtlRecHndl serversListHndl;
CtlRecHndl goOnlineTxtHndl;
CtlRecHndl goOnlineBtnHndl;

Point goOnlineTxtOffscreenPos;
Point goOnlineTxtOnscreenPos;
Point goOnlineBtnOffscreenPos;
Point goOnlineBtnOnscreenPos;

#define SERVER_LIST_SIZE 254
#define SERVER_LIST_BLANKS 10

// The type of entries in out List Manager list
typedef struct {
    uint8_t *memPtr;
    Byte memFlag;
    ServerInfo *serverInfo;
} ListEntry;

ListEntry serverList[SERVER_LIST_SIZE];
unsigned serverListEntries;
bool needListUpdate;

Point lastClickPt;
Long lastClickTime;
Word lastSelection;
ServerInfo *lastServerInfo;
Point eventLoc;

bool networkUp;
bool networkDown;

#pragma databank 1
#pragma toolparms 1
Word Compare(ListEntry *memberA, ListEntry *memberB) {
    if (memberA->memFlag & memNever) {
        return 1;
    } else if (memberB->memFlag & memNever) {
        return 0;
    } else {
        if (CompareStrings(0, (Ptr)memberA->memPtr, (Ptr)memberB->memPtr)
            == 0xFFFF) {
            return 0;
        } else {
            return 1;
        }
    }
}
#pragma toolparms 0
#pragma databank 0

void AddServerEntry(ServerInfo *serverInfo) {
    unsigned i;

    if (!UTF8ToMacRoman(serverInfo->name))
        return;
    
    // If this matches an existing entry, just update that one.
    for (i = 0; i < serverListEntries; i++) {
        if (serverList[i].serverInfo->address == serverInfo->address
            && serverList[i].serverInfo->port == serverInfo->port)
            break;
    }
    
    if (i == serverListEntries) {
        // allocating a new entry
        if (i == SERVER_LIST_SIZE)
            return; // no more space in list
        
        serverList[i].serverInfo = malloc(sizeof(ServerInfo));
        if (serverList[i].serverInfo == NULL)
            return;
        
        serverListEntries++;
        serverList[i].memFlag = 0;
    } else {
        // updating an existing entry
        
        // skip update if entry is unchanged
        if (serverList[i].serverInfo->name[0] == serverInfo->name[0]
            && memcmp(serverList[i].serverInfo->name + 1, serverInfo->name + 1,
            serverInfo->name[0]) == 0)
            return;
    }

    *serverList[i].serverInfo = *serverInfo;
    serverList[i].serverInfo->hostName = NULL;
    serverList[i].memPtr = serverList[i].serverInfo->name;

    needListUpdate = true;
}

void DoMDNS(void) {
    Handle dgmHandle;
    unsigned i;

    if (mdnsActive) {
        if (GetTick() - lastQueryTime > interval) {
            MDNSSendQuery(ipid);
            lastQueryTime = GetTick();
            if (interval < MAX_INTERVAL)
                interval *= 2;
        }

        needListUpdate = false;
        i = 0;
        do {
            TCPIPPoll();
            dgmHandle = TCPIPGetNextDatagram(ipid, protocolUDP, 0xC000);
            if (toolerror())
                break;
            if (dgmHandle != NULL) {
                MDNSProcessPacket(dgmHandle, AddServerEntry);
                DisposeHandle(dgmHandle);
            }
        } while (dgmHandle != NULL && ++i < 10);
        
        if (needListUpdate) {
            if (serverListEntries > SERVER_LIST_BLANKS) {
                NewList2(NULL, 0xFFFF, (Ref)serverList, refIsPointer,
                    serverListEntries, (Handle)serversListHndl);
                SortList2(SORT_CASE_INSENSITIVE, (Handle)serversListHndl);
            } else {
                SortList2((Pointer)((uintptr_t)Compare | 0x80000000),
                    (Handle)serversListHndl);
                DrawMember2(0, (Handle)serversListHndl);
            }
        }
    }
}

void StopMDNS(void) {
    if (mdnsActive) {
        TCPIPLogout(ipid);
        mdnsActive = false;
    }
}

bool StartMDNS(void) {
    static const uint8_t smbName[] = "\x04_smb\x04_tcp\x05local";

    StopMDNS();

    ipid = TCPIPLogin(userid(), MDNS_IP, MDNS_PORT, 0, 0x40);
    if (toolerror())
        return false;

    // Don't send from the mDNS port, which indicates a full mDNS implementation
    if (TCPIPGetSourcePort(ipid) == MDNS_PORT)
        TCPIPSetSourcePort(ipid, 59627);
    
    MDNSInitQuery(smbName);

    mdnsActive = true;
    lastQueryTime = 0;
    interval = INITIAL_INTERVAL / 2;
    
    DoMDNS();
    return true;
}

void DisplayError(unsigned errorCode) {
    if (errorCode != canceled) {
        InitCursor();
        AlertWindow(awResource+awButtonLayout, NULL, errorCode);
    }
}

#pragma databank 1
static void DrawContents(void) {
    Word origResourceApp = GetCurResourceApp();
    SetCurResourceApp(MMStartUp());

    PenNormal();                    /* use a "normal" pen */
    DrawControls(GetPort());        /* draw controls in window */

    SetCurResourceApp(origResourceApp);
}
#pragma databank 0

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

void ClearListSelection(void) {
    unsigned i;

    for (i = 0; i < serverListEntries; i++) {
        if (serverList[i].memFlag & memSelected) {
            serverList[i].memFlag &= ~memSelected;
            DrawMember2(i + 1, (Handle)serversListHndl);
            break;
        }
    }
}

void ClearAddressLine(void) {
    SetLETextByID(wPtr, addressLine, (StringPtr)"");
}

/*
 * Show the "Go Online" butten and descriptive text.
 *
 * Note: These controls are moved in/out of the visible area rather than
 * actually being hidden via the Control Manager, because the Control Panel
 * will unhide hidden controls.
 */
void ShowGoOnlineControls(void) {
    if (!TCPIPGetConnectStatus()) {
        MoveControl(goOnlineTxtOnscreenPos.h, goOnlineTxtOnscreenPos.v,
            goOnlineTxtHndl);
        MoveControl(goOnlineBtnOnscreenPos.h, goOnlineBtnOnscreenPos.v,
            goOnlineBtnHndl);
    }
}

void HideGoOnlineControls(void) {
    MoveControl(goOnlineTxtOffscreenPos.h, goOnlineTxtOffscreenPos.v,
        goOnlineTxtHndl);
    MoveControl(goOnlineBtnOffscreenPos.h, goOnlineBtnOffscreenPos.v,
        goOnlineBtnHndl);
}

void DoConnect(void)
{
    AddressParts addressParts = {0};
    CtlRecHndl ctl;
    unsigned errorCode;
    LongWord connectionID;
    LongWord sessionID;
    unsigned i;
    
    WaitCursor();

    if (FindTargetCtl() == GetCtlHandleFromID(wPtr, addressLine)) {
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
        
        addressParts.displayName = addressParts.host;
    } else {
        static char host[16];
        static char port[6];

        for (i = 0; i < serverListEntries; i++) {
            if (serverList[i].memFlag & memSelected) {
                sprintf(host, "%u.%u.%u.%u",
                    ((uint8_t*)&serverList[i].serverInfo->address)[0],
                    ((uint8_t*)&serverList[i].serverInfo->address)[1],
                    ((uint8_t*)&serverList[i].serverInfo->address)[2],
                    ((uint8_t*)&serverList[i].serverInfo->address)[3]);
                sprintf(port, "%u", serverList[i].serverInfo->port);

                addressParts.host = host;
                addressParts.port = port;
                addressParts.displayName =
                    p2cstr((char*)serverList[i].serverInfo->name);
                break;
            }
        }
        
        if (i == serverListEntries) {
            DisplayError(noServerNameError);
            goto fixcaret;
        }
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
    
    errorCode = LoginToSMBServer(&addressParts, connectionID, &sessionID);
    if (errorCode) {
        ReleaseConnection(connectionID);
        DisplayError(errorCode);
        goto fixcaret;
    }
    ReleaseConnection(connectionID);

    errorCode = MountSMBVolumes(&addressParts, sessionID);
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
    InitCursor();
}

void DoHit(Long ctlID, CtlRecHndl ctlHandle)
{
    if (!wPtr)  /* shouldn't happen */
        return;

    if (ctlID == connectBtn) {
        DoConnect();
    } else if (ctlID == goOnlineBtn) {
        TCPIPConnect(NULL);
        if (!toolerror() || toolerror() == terrCONNECTED)
            HideGoOnlineControls();
    } else if (ctlHandle == addressLineHndl) {
        ClearListSelection();
    } else if (ctlHandle == serversListHndl) {
        ClearAddressLine();
        SubPt(&eventLoc, &lastClickPt);
        if (GetTick() - lastClickTime <= GetDblTime()
            && lastClickPt.h >= -5 && lastClickPt.h <= 5
            && lastClickPt.v >= -3 && lastClickPt.v <= 3
            && NextMember2(0, (Handle)serversListHndl) == lastSelection
            && lastSelection != 0
            && (serverList[lastSelection - 1].memFlag & memNever) == 0
            && serverList[lastSelection - 1].serverInfo == lastServerInfo) {
            DoConnect();
            lastClickTime = 0;
            lastSelection = 0;
        } else {
            lastClickPt = eventLoc;
            lastClickTime = GetTick();
            lastSelection = NextMember2(0, (Handle)serversListHndl);
            if (lastSelection != 0)
                lastServerInfo = serverList[lastSelection - 1].serverInfo;
        }
    } else if (ctlID == 0xFFFFFFFF) {
        // Scroll bar in list control
        if (FindTargetCtl() == serversListHndl)
            ClearAddressLine();
    }
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
    if (toolerror() || ctl != addressLineHndl)
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

#pragma toolparms 1
#pragma databank 1
pascal Word RequestHandler(Word reqCode, void *dataIn, void *dataOut) {
    if (reqCode == TCPIPSaysNetworkUp) {
        networkUp = true;
        networkDown = false;
    } else if (reqCode == TCPIPSaysNetworkDown) {
        networkDown = true;
        networkUp = false;
    }
    return 0;
}
#pragma databank 0
#pragma toolparms 0

void DoCreate(WindowPtr windPtr)
{
    unsigned i;

    wPtr = windPtr;
    
    if (GetMasterSCB() & scbColorMode) {
        NewControl2(wPtr, resourceToResource, cdevWindow);
    } else {
        NewControl2(wPtr, resourceToResource, cdevWindow+320);
    }
    
    goOnlineTxtHndl = GetCtlHandleFromID(wPtr, goOnlineTxt);
    goOnlineTxtOffscreenPos.h = (*goOnlineTxtHndl)->ctlRect.h1;
    goOnlineTxtOffscreenPos.v = (*goOnlineTxtHndl)->ctlRect.v1;
    goOnlineTxtOnscreenPos.h = goOnlineTxtOffscreenPos.h - GO_ONLINE_OFFSET;
    goOnlineTxtOnscreenPos.v = goOnlineTxtOffscreenPos.v - GO_ONLINE_OFFSET;

    goOnlineBtnHndl = GetCtlHandleFromID(wPtr, goOnlineBtn);
    goOnlineBtnOffscreenPos.h = (*goOnlineBtnHndl)->ctlRect.h1;
    goOnlineBtnOffscreenPos.v = (*goOnlineBtnHndl)->ctlRect.v1;
    goOnlineBtnOnscreenPos.h = goOnlineBtnOffscreenPos.h - GO_ONLINE_OFFSET;
    goOnlineBtnOnscreenPos.v = goOnlineBtnOffscreenPos.v - GO_ONLINE_OFFSET;

    serversListHndl = GetCtlHandleFromID(wPtr, serversLst);
    addressLineHndl = GetCtlHandleFromID(wPtr, addressLine);
    
    lastClickTime = 0;
    lastSelection = 0;
    
    for (i = 0; i < SERVER_LIST_BLANKS; i++) {
        serverList[i].memPtr = (uint8_t*)"";
        serverList[i].memFlag = memDisabled | memNever;
    }
    NewList2(NULL, 1, (Ref)serverList, refIsPointer, SERVER_LIST_BLANKS,
            (Handle)serversListHndl);
    
    serverListEntries = 0;

    if (!StartMDNS()) {
        ShowGoOnlineControls();
    }
    
    AcceptRequests("\pTCP/IP~STH~SMBCDev~", userid(),
        (WordProcPtr)RequestHandler);
}

void DoEvent(EventRecord *event)
{
    Word key;
    CtlRecHndl ctl;

    if (event->what == keyDownEvt || event->what == autoKeyEvt) {
        key = event->message & 0xFF;
        if ((event->modifiers & appleKey) && (key == 'a' || key == 'A')) {
            // OA-A -> select all
            ctl = FindTargetCtl();
            if (toolerror() || GetCtlID(ctl) != addressLine)
                return;
            LESetSelect(0, 256, (LERecHndl)GetCtlTitle(ctl));
            event->what = nullEvt;
        } else if (key == TAB) {
            ctl = FindTargetCtl();
            if (toolerror())
                return;
            if (ctl == addressLineHndl) {
                ClearAddressLine();
            } else if (ctl == serversListHndl) {
                ClearListSelection();
            }
        }
    } else {
        eventLoc = event->where;
    }
}

void DoClose(void) {
    AcceptRequests(NULL, userid(), NULL);

    StopMDNS();

    wPtr = NULL;
}

void DoRun(void) {
    if (networkUp) {
        StartMDNS();
        HideGoOnlineControls();
        networkUp = false;
    }
    
    if (networkDown) {
        StopMDNS();
        if (serverList[0].memFlag & memNever)
            ShowGoOnlineControls();
        networkDown = false;
    }
    
    DoMDNS();
}

LongWord CDEVMain (LongWord data2, LongWord data1, Word message)
{
    long result = 0;

    switch(message) {
    case MachineCDEV:   result = DoMachine();               break;
    case HitCDEV:       DoHit(data2, (CtlRecHndl)data1);    break;
    case EditCDEV:      DoEdit(data1 & 0xFFFF);             break;
    case CreateCDEV:    DoCreate((WindowPtr)data1);         break;
    case CloseCDEV:     DoClose();                          break;
    case EventsCDEV:    DoEvent((EventRecord*)data1);       break;
    case RunCDEV:       DoRun();                            break;
    }

    return result;
}
