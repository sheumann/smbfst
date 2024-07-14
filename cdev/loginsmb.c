/*
 * Copyright (c) 2024 Stephen Heumann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
#include "cdev/configfile.h"
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
#define saveInfoChk     11

static SMBAuthenticateRec authenticatePB = {
    .pCount = 12,
    .fileSysID = smbFSID,
    .commandNum = SMB_AUTHENTICATE,
};

static GrafPortPtr oldPort;
static Pointer oldParamPtr;
static WindowPtr windPtr = NULL;
static EventRecord eventRec;
static bool setParamPtr = false;

static char username[257];
static char password[257];
static char domain[257];
static bool saveInfo;

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

        SetCtlValueByID(address->usingSavedLoginInfo, windPtr, saveInfoChk);

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
    saveInfo = GetCtlValueByID(windPtr, saveInfoChk);

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
    AddressParts *address) {
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

    authenticatePB.flags = 0;
    authenticatePB.connectionID = connectionID;
    authenticatePB.userName = user->text;
    authenticatePB.userNameSize = user->length;
    authenticatePB.userDomain = dom->text;
    authenticatePB.userDomainSize = dom->length;

    if (address && address->usingSavedLoginInfo) {
        memcpy(authenticatePB.ntlmv2Hash, address->ntlmv2Hash, 16);
        authenticatePB.flags |= AUTH_FLAG_HAVE_NTLMV2_HASH;
        if (address->anonymous)
            authenticatePB.flags |= AUTH_FLAG_ANONYMOUS;
        authenticatePB.password = NULL;
        authenticatePB.passwordSize = 0;
    } else {
        authenticatePB.password = pass->text;
        authenticatePB.passwordSize = pass->length;
        if (saveInfo)
            authenticatePB.flags |= AUTH_FLAG_GET_NTLMV2_HASH;
    }

    FSTSpecific(&authenticatePB);
    if (toolerror()) {
        result = authenticateError;
        if (address && address->usingSavedLoginInfo) {
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
    
    if ((address->username != NULL && address->password != NULL)
        || address->usingSavedLoginInfo) {
        result = TryLogin(connectionID, sessionID, address);
        if (result == 0)
            goto done;
    }

    if (doingBoot) {
        result = authenticateError;
        goto done;
    }

    do {
        if (!DoLoginWindow(address)) {
            result = canceled;
            goto done;
        }
        result = TryLogin(connectionID, sessionID, NULL);
        
        address->usingSavedLoginInfo = false;

        if (saveInfo) {
            address->usingSavedLoginInfo = SaveLoginInfo(address->host,
                domain+1, username+1, authenticatePB.ntlmv2Hash,
                username[0] == 0 && password[0] == 0);
        } else {
            DeleteSavedInfo(address->host, true, true);
        }
    } while (result != 0);

done:
    memset(authenticatePB.ntlmv2Hash, 0, 16);
    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));
    memset(domain, 0, sizeof(domain));
    CloseLoginWindow();
    return result;
}
