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

#define GENERATE_ROOT
#include "defs.h"
#include <gsos.h>
#include <stdio.h>
#include <orca.h>
#include <stddef.h>
#include <tcpip.h>
#include <locator.h>
#include <uchar.h>
#include <stdint.h>
#include <string.h>

#include <memory.h>

#include "fst/fstspecific.h"
#include "rpc/rpc.h"
#include "rpc/srvsvc.h"

SMBConnectRec connectPB = {
    .pCount = 7,
    .fileSysID = smbFSID,
    .commandNum = SMB_CONNECT,
    .serverIP = 0x79797979,
    .serverPort = 0,
    .serverName = NULL,
    .flags = 0x00FF,
};

SMBAuthenticateRec authenticatePB = {
    .pCount = 11,
    .fileSysID = smbFSID,
    .commandNum = SMB_AUTHENTICATE,
    .flags = 0,
};

SMBConnectionRec connectionReleasePB = {
    .pCount = 3,
    .fileSysID = smbFSID,
    .commandNum = SMB_CONNECTION_RELEASE,
};

SMBSessionRec sessionReleasePB = {
    .pCount = 3,
    .fileSysID = smbFSID,
    .commandNum = SMB_SESSION_RELEASE,
};

struct {
    Word length;
    char text[4];
} volName = {4, "IPC$"};

SMBMountRec mountPB = {
    .pCount = 7,
    .fileSysID = smbFSID,
    .commandNum = SMB_MOUNT,
    .volName = (GSString255*)&volName,
};

DAccessRecGS dControlPB = {
    .pCount = 5,
    .code = eject,
    .list = NULL,
    .requestCount = 0,
};

char ipcShareName[] = "IPC$";

int main(int argc, char *argv[]) {
    cvtRec theCvtRec;
    Handle infoHandle;
    ShareInfoRec *shareInfo;
    
    size_t len;
    unsigned i,j;

    static char16_t user[100];
    static char16_t password[100];
    static char16_t domain[100];
    static char16_t share[100];

    if (argc < 5) {
        printf("Usage: %s server username password domain\n",
            argv[0]);
        return 0;
    }

    LoadOneTool(54, 0x200);
    TCPIPStartUp();
    
    TCPIPConvertIPCToHex(&theCvtRec, argv[1]);
    connectPB.serverIP = theCvtRec.cvtIPAddress;
    
    TCPIPConnect(NULL);

    FSTSpecific(&connectPB);
    if (toolerror()) {
        printf("Connect error: $%02x\n", toolerror());
        return 0;
    }
    
    authenticatePB.connectionID = connectPB.connectionID;

    len = strlen(argv[2]);
    if (len > 100)
        len = 100;
    for (i = 0; i < len; i++) {
        user[i] = argv[2][i];
    }
    authenticatePB.userName = user;
    authenticatePB.userNameSize = len*2;

    len = strlen(argv[3]);
    if (len > 100)
        len = 100;
    for (i = 0; i < len; i++) {
        password[i] = argv[3][i];
    }
    authenticatePB.password = password;
    authenticatePB.passwordSize = len*2;

    len = strlen(argv[4]);
    if (len > 100)
        len = 100;
    for (i = 0; i < len; i++) {
        domain[i] = argv[4][i];
    }
    authenticatePB.userDomain = domain;
    authenticatePB.userDomainSize = len*2;

    if (strlen(argv[1]) + strlen(ipcShareName) + 3 > 100)
        return 0;
    i = 0;
    share[i++] = '\\';
    share[i++] = '\\';
    len = strlen(argv[1]);
    for (j = 0; j < len; j++) {
        share[i++] = argv[1][j];
    }
    share[i++] = '\\';
    len = strlen(ipcShareName);
    for (j = 0; j < len; j++) {
        share[i++] = ipcShareName[j];
    }
    mountPB.shareName = share;
    mountPB.shareNameSize = i*2;

    FSTSpecific(&authenticatePB);
    if (toolerror()) {
        printf("Authenticate error: $%02x\n", toolerror());
        connectionReleasePB.connectionID = connectPB.connectionID;
        FSTSpecific(&connectionReleasePB);
        return 0;
    }

    connectionReleasePB.connectionID = connectPB.connectionID;
    FSTSpecific(&connectionReleasePB);

    mountPB.sessionID = authenticatePB.sessionID;
    FSTSpecific(&mountPB);

    if (toolerror()) {
        printf("Mount error: $%02x\n", toolerror());
        sessionReleasePB.sessionID = authenticatePB.sessionID;
        FSTSpecific(&sessionReleasePB);
        return 0;
    }

    sessionReleasePB.sessionID = authenticatePB.sessionID;
    FSTSpecific(&sessionReleasePB);

    infoHandle = EnumerateShares(mountPB.devNum);
    if (!infoHandle) {
        printf("Error enumerating shares\n");
        return 0;
    }
    
    dControlPB.devNum = mountPB.devNum;
    DControl(&dControlPB);
    
    printf("Shares on server:\n");
    shareInfo = (ShareInfoRec *)*infoHandle;
    for (uint32_t i = 0; i < shareInfo->entryCount; i++) {
        ShareInfoString *name = shareInfo->shares[i].shareName;
        for (uint32_t j = 0; j < name->len - 1; j++) {
            char16_t ch = name->str[j];
            putchar(ch < 128 ? ch : '?');
        }
        printf("\n");
    }
    DisposeHandle(infoHandle);

    return 0;
}
