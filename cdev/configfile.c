#define USE_BLANK_SEG
#include "defs.h"
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <resources.h>
#include <memory.h>
#include <gsos.h>
#include <orca.h>
#include "cdev/configfile.h"

#define DIR_FILE_TYPE 0x0F
#define CFG_FILE_TYPE 0x5A
#define FULL_ACCESS (destroyEnable | renameEnable | readEnable | writeEnable)

#define rSMBLoginInfo 0x0001
#define rSMBShareList 0x0002

GSString32 configDirName  = {25, "*:System:Preferences"};
GSString32 configFileName = {31, "*:System:Preferences:SMB.Config"};

static char nameBuf[257];

static LoginInfo loginInfo = {0};

static void SetHostName(const char *host) {
    unsigned i;

    nameBuf[0] = min(strlen(host), 255);
    for (i = 0; i < nameBuf[0]; i++) {
        nameBuf[i+1] = tolower(host[i]);
    }
}

void GetSavedLoginInfo(AddressParts *addressParts) {
    Word fileID;
    Word depth;
    Handle loginInfoHandle;
    size_t infoSize;

    if (addressParts->host == NULL)
        return;

    fileID = OpenResourceFile(readEnable, NULL, (Pointer)&configFileName);
    if (toolerror())
        return;

    depth = SetResourceFileDepth(1);

    SetHostName(addressParts->host);

    loginInfoHandle = RMLoadNamedResource(rSMBLoginInfo, nameBuf);
    if (toolerror())
        goto cleanup;

    infoSize = GetHandleSize(loginInfoHandle);
    if (infoSize < 4 || infoSize >= sizeof(LoginInfo))
        goto cleanup;
    
    memcpy(&loginInfo, *loginInfoHandle, infoSize);

    infoSize -= 4;
    if (loginInfo.userOffset >= infoSize)
        goto cleanup;

    // ensure strings are null-terminated, even if info is corrupt
    loginInfo.buf[infoSize] = 0;

    addressParts->domain = loginInfo.buf;
    addressParts->username = loginInfo.buf + loginInfo.userOffset;
    addressParts->anonymous = loginInfo.anonymous;
    addressParts->ntlmv2Hash = loginInfo.ntlmv2Hash;
    addressParts->usingSavedLoginInfo = true;

cleanup:
    SetResourceFileDepth(depth);
    CloseResourceFile(fileID);
}

void SaveLoginInfo(char *host, char *domain, char *username, 
    Byte ntlmv2Hash[16], bool anonymous) {
    Word fileID;
    Word depth;
    Handle loginInfoHandle = NULL;
    Long rsrcID;
    size_t domainLen, usernameLen;
    LoginInfo *loginInfo;

    static CreateRecGS createRec = {
        .pCount = 5,
        .pathname = (GSString255*)&configDirName,
        .access = FULL_ACCESS,
        .fileType = DIR_FILE_TYPE,
        .auxType = 0,
        .storageType = directoryFile,
    };

    // Remove any existing login info for this server
    rsrcID = DeleteSavedInfo(host, true, false);

    // Create *:System:Preferences directory (if it does not exist)
    CreateGS(&createRec);

    // Create and initialize config file (if it does not exist)
    CreateResourceFile(0x0000, CFG_FILE_TYPE, FULL_ACCESS,
        (Pointer)&configFileName);

    // Open resource file
    fileID = OpenResourceFile(readWriteEnable, NULL, (Pointer)&configFileName);
    if (toolerror())
        return;

    depth = SetResourceFileDepth(1);
    
    // Set up new login info record
    domainLen = strlen(domain) + 1;
    usernameLen = strlen(username) + 1;
    
    if (domainLen > 256 || usernameLen > 256)
        goto cleanup;

    loginInfoHandle = NewHandle(
        offsetof(LoginInfo, buf) + domainLen + usernameLen,
        MMStartUp(), attrFixed, 0);
    if (toolerror()) {
        loginInfoHandle = NULL;
        goto cleanup;
    }
    
    loginInfo = (LoginInfo*)*loginInfoHandle;
    loginInfo->userOffset = domainLen;
    loginInfo->anonymous = anonymous;
    memcpy(loginInfo->ntlmv2Hash, ntlmv2Hash, 16);
    strcpy(loginInfo->buf, domain);
    strcpy(loginInfo->buf + domainLen, username);

    // Add the new resource and name it
    if (rsrcID == 0) {
        rsrcID = UniqueResourceID(0x0000, rSMBLoginInfo);
        if (toolerror())
            goto cleanup;
    }

    AddResource(loginInfoHandle, attrFixed, rSMBLoginInfo, rsrcID);
    if (toolerror())
        goto cleanup;

    loginInfoHandle = NULL; // now owned by Resource Manager

    SetHostName(host);
    RMSetResourceName(rSMBLoginInfo, rsrcID, nameBuf);

cleanup:
    if (loginInfoHandle)
        DisposeHandle(loginInfoHandle);
    SetResourceFileDepth(depth);
    CloseResourceFile(fileID); 
}

Long DeleteSavedInfo(char *host, bool deleteLoginInfo,
    bool deleteAutoMountList) {
    Word fileID;
    Word depth;
    Long rsrcID;
    Word rsrcFileID;
    Handle loginInfoHandle;
    RefNumRecGS flushRec = {.pCount = 1};

    fileID = OpenResourceFile(readWriteEnable, NULL, (Pointer)&configFileName);
    if (toolerror())
        return 0;

    depth = SetResourceFileDepth(1);
    
    SetHostName(host);

    rsrcID = RMFindNamedResource(rSMBLoginInfo, nameBuf, &rsrcFileID);
    if (toolerror()) {
        rsrcID = 0;
        goto cleanup;
    }

    if (deleteLoginInfo) {
        loginInfoHandle = LoadResource(rSMBLoginInfo, rsrcID);
        if (!toolerror()) {
            /* Write over old login info with zeros */
            memset(*loginInfoHandle, 0, GetHandleSize(loginInfoHandle));
            MarkResourceChange(true, rSMBLoginInfo, rsrcID);
            WriteResource(rSMBLoginInfo, rsrcID);
            flushRec.refNum = fileID;
            FlushGS(&flushRec);
        }
        RMSetResourceName(rSMBLoginInfo, rsrcID, "\p");
        RemoveResource(rSMBLoginInfo, rsrcID);
    }
    if (deleteAutoMountList) {
        RemoveResource(rSMBShareList, rsrcID);
    }
    CompactResourceFile(0, fileID);

cleanup:
    SetResourceFileDepth(depth);
    CloseResourceFile(fileID);   
    return rsrcID; 
}

void SaveAutoMountList(char *host, Handle listHandle) {
    Word fileID;
    Word depth;
    Long rsrcID;
    Word rsrcFileID;

    /*
     * Auto-mount is only allowed if login info is saved, so the config
     * file should already exist and have login info for the host.
     * The share list is given the same ID as the login info.
     */
    fileID = OpenResourceFile(readWriteEnable, NULL, (Pointer)&configFileName);
    if (toolerror())
        return;

    depth = SetResourceFileDepth(1);
    
    SetHostName(host);

    rsrcID = RMFindNamedResource(rSMBLoginInfo, nameBuf, &rsrcFileID);
    if (toolerror())
        goto cleanup;

    RemoveResource(rSMBShareList, rsrcID);
    AddResource(listHandle, attrFixed, rSMBShareList, rsrcID);

cleanup:
    SetResourceFileDepth(depth);
    CloseResourceFile(fileID);  
}

void ForEachAutoMountList(void (*f)(Handle,Handle,char*)) {
    Word fileID;
    Word depth;
    Long count;
    Word i;
    Handle shareListHandle;
    Handle loginInfoHandle;

    /*
     * Auto-mount is only allowed if login info is saved, so the config
     * file should already exist and have login info for the host.
     * The share list is given the same ID as the login info.
     */
    fileID = OpenResourceFile(readEnable, NULL, (Pointer)&configFileName);
    if (toolerror())
        return;

    depth = SetResourceFileDepth(1);
    
    count = CountResources(rSMBShareList);

    for (i = 1; i != 0 && count != 0; i++) {
        shareListHandle = LoadResource(rSMBShareList, i);
        if (toolerror())
            continue;
        count--;
        DetachResource(rSMBShareList, i);

        loginInfoHandle = LoadResource(rSMBLoginInfo, i);
        if (toolerror())
            goto cont2;
        DetachResource(rSMBLoginInfo, i);

        RMGetResourceName(rSMBLoginInfo, i, nameBuf);
        if (toolerror())
            goto cont1;
        nameBuf[nameBuf[0]+1] = '\0';

        f(loginInfoHandle, shareListHandle, nameBuf+1);

cont1:  DisposeHandle(loginInfoHandle);
cont2:  DisposeHandle(shareListHandle);
    };

cleanup:
    SetResourceFileDepth(depth);
    CloseResourceFile(fileID);
}
