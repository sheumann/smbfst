#include "defs.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <list.h>
#include <memory.h>
#include <quickdraw.h>
#include <window.h>
#include <resources.h>
#include <control.h>
#include <tcpip.h>
#include <gsos.h>
#include <orca.h>
#include "cdev/mountsmbvol.h"
#include "cdev/charset.h"
#include "cdev/errorcodes.h"
#include "fst/fstspecific.h"
#include "rpc/srvsvc.h"


#define sharesWindow    5000

#define selectSharesTxt 1
#define sharesLst       3
#define cancelMountBtn  4
#define mountBtn        5

// Maximum number of members in a List Manager list
#define MAX_LIST_SIZE 0x3fff

// Maximum number of list entries to select automatically
#define AUTO_SELECT_LIMIT 16

// The type of entries in out List Manager list
typedef struct {
    char *memPtr;
    Byte memFlag;
    unsigned index;
} ListEntry;

GSString32 volNameBuffer;

static SMBMountRec mountPB = {
    .pCount = 7,
    .fileSysID = smbFSID,
    .commandNum = SMB_MOUNT,
    .volName = (GSString255*)&volNameBuffer,
};

ResultBuf32 devName = {32};
ResultBuf255 volName = {255};

DInfoRec dInfoPB = {
    .pCount = 2,
    .devName = &devName,
};

VolumeRec volumePB = {
    .pCount = 2,
    .devName = &devName.bufString,
    .volName = &volName,
};

DAccessRecGS dControlPB = {
    .pCount = 5,
    .code = eject,
    .list = NULL,
    .requestCount = 0,
};

static GrafPortPtr oldPort;
static WindowPtr windPtr = NULL;
static EventRecord eventRec;

static bool DoSharesWindow(ListEntry *list, unsigned listSize) {
    Handle listCtlHandle;
    LongWord controlID;

    if (windPtr == NULL) {
        oldPort = GetPort();
        windPtr = NewWindow2(NULL, 0, NULL, NULL, refIsResource, sharesWindow,
            rWindParam1);
        if (toolerror()) {
            windPtr = NULL;
            return false;
        }
        SetPort(windPtr);

        if (GetMasterSCB() & scbColorMode)
            MoveWindow(10+160, 22, windPtr);

        listCtlHandle = (Handle)GetCtlHandleFromID(windPtr, sharesLst);
        NewList2(NULL, 1, (Ref)list, refIsPointer, listSize, listCtlHandle);
        SortList2((Pointer)0x00000001, listCtlHandle);

        ShowWindow(windPtr);
    }
    
    do {
        controlID = DoModalWindow(&eventRec, NULL, NULL, NULL, mwIBeam);
        TCPIPPoll();
    } while (controlID != cancelMountBtn && controlID != mountBtn);

    InitCursor();

    return (controlID == mountBtn);
}

static void CloseSharesWindow(void) {
    if (windPtr) {
        CloseWindow(windPtr);
        SetPort(oldPort);
        windPtr = NULL;
    }
}

static unsigned MountVolume(char16_t *shareName, uint16_t shareNameSize,
    char *volName, AddressParts *address, LongWord sessionID) {
    UTF16String *hostName;
    uint32_t nameLen;
    char16_t *nameBuffer;    
    
    hostName = MacRomanToUTF16(address->host);
    if (hostName == NULL)
        return oomError;
    
    nameLen = 3 * sizeof(char16_t) + hostName->length + shareNameSize;
    if (nameLen > UINT16_MAX) {
        free(hostName);
        return mountError;
    }
    
    nameBuffer = malloc(nameLen);
    if (nameBuffer == NULL) {
        free(hostName);
        return oomError;
    }
    
    /*
     * We limit the volume name to 31 characters, truncating longer ones with
     * an ellipsis.  GS/OS can handle longer volume names, but the Finder can
     * only handle up to 31 characters and Standard File can handle up to 33,
     * so volume names longer than that are not really usable in desktop apps.
     */
    volNameBuffer.length = min(strlen(volName), 32);
    memcpy(volNameBuffer.text, volName, volNameBuffer.length);
    if (volNameBuffer.length == 32) {
        volNameBuffer.length = 31;
        volNameBuffer.text[30] = '\xC9';  // ... character
    }
    
    // Construct UNC path for share (\\hostname\sharename)
    nameBuffer[0] = '\\';
    nameBuffer[1] = '\\';
    memcpy(nameBuffer+2, hostName->text, hostName->length);
    nameBuffer[hostName->length/2 + 2] = '\\';
    memcpy(nameBuffer + hostName->length/2 + 3, shareName, shareNameSize);
    free(hostName);

    mountPB.sessionID = sessionID;
    mountPB.shareName = nameBuffer;
    mountPB.shareNameSize = nameLen;
    FSTSpecific(&mountPB);
    if (toolerror()) {
        free(nameBuffer);
        return mountError;
    }

    free(nameBuffer);

    dInfoPB.devNum = mountPB.devNum;
    DInfo(&dInfoPB);
    if (toolerror())
        return mountError;

    // This call ensures the share is recognized as an online volume.
    VolumeGS(&volumePB);

    return 0;
}

/*
 * Build a list of shares suitable for use with the list manager, based on
 * share info in infoRec.
 * 
 * Returns an error code, or 0 on success.  On successful completion, *listPtr
 * is set to point to the list, and *listSize is set to its size.
 *
 * The list and each name string used in it are allocated with malloc; the
 * caller is responsible for freeing them.
 */
static unsigned BuildShareList(const ShareInfoRec *infoRec,
    ListEntry **listPtr, unsigned *listSize) {
    unsigned n;
    unsigned long i;
    unsigned entryCount;
    ListEntry *list;
    ListEntry *entry;
    
    n = min(infoRec->entryCount, MAX_LIST_SIZE);
    
    list = malloc(n * sizeof(ListEntry));
    if (list == NULL)
        return oomError;
    
    entry = list;
    entryCount = 0;
    for (i = 0; i < n; i++) {
        if ((infoRec->shares[i].shareType & ~STYPE_TEMPORARY)
            == STYPE_DISKTREE) {
            entry->memPtr = UTF16ToMacRoman(infoRec->shares[i].shareName->len,
                infoRec->shares[i].shareName->str);
            if (entry->memPtr == NULL)
                break;

            if (n <= AUTO_SELECT_LIMIT + 1) {
                entry->memFlag = memSelected;
            } else {
                entry->memFlag = 0x00;
            }

            entry->index = i;
            entry++;
            entryCount++;
        }
    }

    if (entryCount == 0) {
        free(list);
        return noSharesError;
    }

    *listPtr = list;
    *listSize = entryCount;

    return 0;
}

static unsigned MountSelectedShares(const ListEntry *list, unsigned listSize,
    const ShareInfoRec *infoRec, AddressParts *address, LongWord sessionID) {
    unsigned long i;
    ShareInfoString *shareName;
    unsigned result = 0;

    for (i = 0; i < listSize; i++) {
        if (list[i].memFlag & memSelected) {
            shareName = infoRec->shares[list[i].index].shareName;
            if (shareName->len == 0 || shareName->len > UINT16_MAX / 2) {
                result = mountError;
                continue;
            }
            if (MountVolume(shareName->str, (shareName->len-1) * 2, 
                list[i].memPtr, address, sessionID)) {
                result = mountError;
            }
        }
    }
    
    return result;
}

static void FreeShareList(ListEntry *list, unsigned listSize) {
    unsigned long i;

    for (i = 0; i < listSize; i++) {
        free(list[i].memPtr);
    }
    
    free(list);
}

unsigned MountSMBVolumes(AddressParts *address, LongWord sessionID) {
    UTF16String *shareName = NULL;
    Handle infoHandle;
    ShareInfoRec *infoRec;
    unsigned result;
    ListEntry *list;
    unsigned listSize;
    bool doMount;

    if (address->share != NULL && address->share[0] != '\0') {
        shareName = MacRomanToUTF16(address->share);
        if (shareName == NULL)
            return oomError;
        
        result = MountVolume(shareName->text, shareName->length,
            address->share, address, sessionID);
        
        free(shareName);
        return result;
    } else {
        // Mount IPC$ share
        result = MountVolume(u"IPC$", 4*sizeof(char16_t), "IPC$", address,
            sessionID);
    
        // Get list of shares on server
        infoHandle = EnumerateShares(mountPB.devNum);
        if (!infoHandle)
            result = shareEnumerationError;
        
        // Disconnect from IPC$ share
        dControlPB.devNum = mountPB.devNum;
        DControl(&dControlPB);
        
        if (result != 0)
            return result;
            
        infoRec = (ShareInfoRec *)*infoHandle;
        
        result = BuildShareList(infoRec, &list, &listSize);
        if (result != 0) {
            DisposeHandle(infoHandle);
            return result;
        }
        
        doMount = DoSharesWindow(list, listSize);
        CloseSharesWindow();

        if (doMount)
            MountSelectedShares(list, listSize, infoRec, address, sessionID);
        
        FreeShareList(list, listSize);
        DisposeHandle(infoHandle);

        return 0;
    }
}
