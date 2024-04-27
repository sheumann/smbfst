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

ResultBuf32 devName = {32};
ResultBuf255 volName = {255};

SMBMountRec mountPB = {
    .pCount = 7,
    .fileSysID = smbFSID,
    .commandNum = SMB_MOUNT,
    .volName = &volName.bufString
};

DInfoRec dInfoPB = {
    .pCount = 2,
    .devName = &devName,
};

VolumeRec volumePB = {
    .pCount = 8,
    .devName = &devName.bufString,
    .volName = &volName,
};

int main(int argc, char *argv[]) {
    cvtRec theCvtRec;
    
    size_t len;
    unsigned i,j;

    static char16_t user[100];
    static char16_t password[100];
    static char16_t domain[100];
    static char16_t share[100];

    if (argc < 6) {
        printf("Usage: %s server username password domain sharename\n",
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

    if (strlen(argv[1]) + strlen(argv[5]) + 3 > 100)
        return 0;
    i = 0;
    share[i++] = '\\';
    share[i++] = '\\';
    len = strlen(argv[1]);
    for (j = 0; j < len; j++) {
        share[i++] = argv[1][j];
    }
    share[i++] = '\\';
    len = strlen(argv[5]);
    for (j = 0; j < len; j++) {
        share[i++] = argv[5][j];
    }
    mountPB.shareName = share;
    mountPB.shareNameSize = i*2;
    
    volName.bufString.length = min(strlen(argv[5]), 255);
    memcpy(volName.bufString.text, argv[5], volName.bufString.length);

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
    
    dInfoPB.devNum = mountPB.devNum;
    DInfo(&dInfoPB);
    if (toolerror()) {
        printf("DInfo error: $%02x\n", toolerror());
        return 0;
    }

    Volume(&volumePB);
    if (toolerror()) {
        printf("VolumeGS error: $%02x\n", toolerror());
        return 0;
    }
    
    printf("Mounted ");
    for (unsigned i = 0; i < volName.bufString.length; i++) {
        putchar(volName.bufString.text[i]);
    }
    printf(" on device ");
    for (unsigned i = 0; i < devName.bufString.length; i++) {
        putchar(devName.bufString.text[i]);
    }
    printf("\n");
}
