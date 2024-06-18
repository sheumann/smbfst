#define USE_BLANK_SEG
#include "defs.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <quickdraw.h>
#include <qdaux.h>
#include <window.h>
#include <resources.h>
#include <control.h>
#include <event.h>
#include <lineedit.h>
#include <tcpip.h>
#include <gsos.h>
#include <orca.h>
#include "cdev/smbcdev.h"
#include "cdev/loginsmb.h"
#include "cdev/charset.h"
#include "cdev/errorcodes.h"
#include "fst/fstspecific.h"

// Bit setting in DoModalWindow eventHook value
#define MAP_OA_PERIOD_TO_ESC 0x80000000

#define loginWindow     3000

#define loginTxt        1
#define serverNameTxt   2
#define nameTxt         3
#define nameLine        4
#define passwordTxt     5
#define passwordLine    6
#define domainTxt       7
#define domainLine      8
#define cancelBtn       9
#define loginBtn        10

static SMBAuthenticateRec authenticatePB = {
    .pCount = 11,
    .fileSysID = smbFSID,
    .commandNum = SMB_AUTHENTICATE,
    .flags = 0,
};

static GrafPortPtr oldPort;
static Pointer oldParamPtr;
static WindowPtr windPtr = NULL;
static EventRecord eventRec;
static bool setParamPtr = false;

static char username[257];
static char password[257];
static char domain[257];

#define TAB 0x09

#pragma databank 1
static void EventHook(EventRecord *event) {
    Word key;
    LongWord target;
    CtlRecHndl ctl;

    if ((event->modifiers & (shiftKey | appleKey))
        && (event->what == keyDownEvt || event->what == autoKeyEvt)) {
        key = event->message & 0xFF;
        if (key == TAB) {
            // shift-tab (or OA-tab) -> tab through fields in reverse
            switch (GetCtlID(FindTargetCtl())) {
            case nameLine:      target = domainLine;    break;
            default:
            case passwordLine:  target = nameLine;      break;
            case domainLine:    target = passwordLine;  break;
            }
            ctl = GetCtlHandleFromID(windPtr, target);
            MakeThisCtlTarget(ctl);
            LESetSelect(0, 256, (LERecHndl)GetCtlTitle(ctl));
            event->what = nullEvt;
        } else if ((key == 'a' || key == 'A')
            && (event->modifiers & appleKey)) {
            // OA-A -> select all
            ctl = FindTargetCtl();
            target = GetCtlID(ctl);
            if (toolerror() || (target != nameLine 
                && target != passwordLine && target != domainLine))
                return;
            LESetSelect(0, 256, (LERecHndl)GetCtlTitle(ctl));
            event->what = nullEvt;
        }
    
    }
}
#pragma databank 0

static bool DoLoginWindow(AddressParts *address) {
    LongWord controlID;

    if (windPtr == NULL) {
        oldPort = GetPort();
        oldParamPtr = GetCtlParamPtr();
        SetCtlParamPtr((Pointer)&address->displayName);
        setParamPtr = true;

        windPtr = NewWindow2(NULL, 0, NULL, NULL, refIsResource, loginWindow,
            rWindParam1);
        if (toolerror()) {
            windPtr = NULL;
            return false;
        }
        SetPort(windPtr);

        SetLETextByID(windPtr, nameLine, (StringPtr)username);
        SetLETextByID(windPtr, passwordLine, (StringPtr)password);
        SetLETextByID(windPtr, domainLine, (StringPtr)domain);
        if (username[0] != 0 && password[0] == 0)
            MakeThisCtlTarget(GetCtlHandleFromID(windPtr, passwordLine));

        if (GetMasterSCB() & scbColorMode)
            MoveWindow(10+160, 47, windPtr);

        ShowWindow(windPtr);
    }
    
    InitCursor();
    
    do {
        controlID = DoModalWindow(&eventRec, NULL,
            (VoidProcPtr)((uintptr_t)&EventHook | MAP_OA_PERIOD_TO_ESC),
            NULL, mwIBeam);
        TCPIPPoll();
    } while (controlID != cancelBtn && controlID != loginBtn);

    InitCursor();

    GetLETextByID(windPtr, nameLine, (StringPtr)username);
    GetLETextByID(windPtr, passwordLine, (StringPtr)password);
    GetLETextByID(windPtr, domainLine, (StringPtr)domain);

    return (controlID == loginBtn);
}

static void CloseLoginWindow(void) {
    if (setParamPtr) {
        SetCtlParamPtr(oldParamPtr);
        setParamPtr = false;
    }
    if (windPtr) {
        CloseWindow(windPtr);
        SetPort(oldPort);
        windPtr = NULL;
    }
}

static unsigned TryLogin(LongWord connectionID, LongWord *sessionID,
    bool usingSavedLoginInfo) {
    unsigned result = 0;

    UTF16String *user = NULL;
    UTF16String *pass = NULL;
    UTF16String *dom = NULL;
    
    WaitCursor();

    user = MacRomanToUTF16(username+1);
    pass = MacRomanToUTF16(password+1);
    dom = MacRomanToUTF16(domain+1);

    if (user == NULL || pass == NULL || dom == NULL) {
        result = oomError;
        goto cleanup;
    }

    authenticatePB.connectionID = connectionID;
    authenticatePB.userName = user->text;
    authenticatePB.userNameSize = user->length;
    authenticatePB.password = pass->text;
    authenticatePB.passwordSize = pass->length;
    authenticatePB.userDomain = dom->text;
    authenticatePB.userDomainSize = dom->length;

    FSTSpecific(&authenticatePB);
    if (toolerror()) {
        result = authenticateError;
        if (usingSavedLoginInfo) {
            DisplayError(savedLoginError);
        } else {
            DisplayError(authenticateError);
        }
        goto cleanup;
    }

    *sessionID = authenticatePB.sessionID;

cleanup:
    if (pass)
        memset(pass->text, 0, pass->length);
    free(user);
    free(pass);
    free(dom);
    return result;
}

unsigned LoginToSMBServer(AddressParts *address, LongWord connectionID,
    LongWord *sessionID) {
    unsigned result = 0;

    if (address->username != NULL) {
        strncpy(username+1, address->username, sizeof(username)-2);
        username[0] = strlen(username+1);
    }
    if (address->password != NULL) {
        strncpy(password+1, address->password, sizeof(password)-2);
        password[0] = strlen(password+1);
    }
    if (address->domain != NULL) {
        strncpy(domain+1, address->domain, sizeof(domain)-2);
        domain[0] = strlen(domain+1);
    }
    
    if (address->username != NULL && address->password != NULL) {
        result = TryLogin(connectionID, sessionID,
            address->usingSavedLoginInfo);
        if (result == 0)
            goto done;
    }
    
    do {
        if (!DoLoginWindow(address)) {
            result = canceled;
            goto done;
        }
        result = TryLogin(connectionID, sessionID, false);
    } while (result != 0);

done:
    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));
    memset(domain, 0, sizeof(domain));
    CloseLoginWindow();
    return result;
}
