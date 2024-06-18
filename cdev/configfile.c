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

#define rSMBLoginInfo 0x0001

/*
 * Login Info data structure.
 * buf contains domain, then user and password at designated offsets
 * (all C strings).
 */
typedef struct {
    Word userOffset;
    Word passwordOffset;
    char buf[3 * 256 + 1];
} LoginInfo;

GSString32 configFileName = {31, "*:System:Preferences:SMB.Config"};

static char nameBuf[256];

static LoginInfo loginInfo = {0};

void GetSavedLoginInfo(AddressParts *addressParts) {
    Word fileID;
    unsigned i;
    Word depth;
    Handle loginInfoHandle;
    size_t infoSize;

    if (addressParts->host == NULL)
        return;

    fileID = OpenResourceFile(readEnable, NULL, (Pointer)&configFileName);
    if (toolerror())
        return;

    depth = SetResourceFileDepth(1);

    nameBuf[0] = min(strlen(addressParts->host), 255);
    for (i = 0; i < nameBuf[0]; i++) {
        nameBuf[i+1] = tolower(addressParts->host[i]);
    }
    
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
    if (loginInfo.passwordOffset >= infoSize)
        goto cleanup;

    // ensure strings are null-terminated, even if info is corrupt
    loginInfo.buf[infoSize] = 0;

    addressParts->domain = loginInfo.buf;
    addressParts->username = loginInfo.buf + loginInfo.userOffset;
    addressParts->password = loginInfo.buf + loginInfo.passwordOffset;
    addressParts->usingSavedLoginInfo = true;

cleanup:
    SetResourceFileDepth(depth);
    CloseResourceFile(fileID);
}
