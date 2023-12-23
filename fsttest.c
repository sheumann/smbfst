#include <gsos.h>
#include <stdio.h>
#include <orca.h>
#include <stddef.h>
#include <tcpip.h>
#include <locator.h>
#include <uchar.h>
#include <stdint.h>

#include <memory.h>

#include "fstspecific.h"

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

SMBMountRec mountPB = {
    .pCount = 6,
    .fileSysID = smbFSID,
    .commandNum = SMB_MOUNT,
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

int main(int argc, char *argv[]) {
    cvtRec theCvtRec;
    
    size_t len;
    unsigned i;

    static char16_t user[100];
    static char16_t password[100];
    static char16_t domain[100];
    static char16_t share[100];
    uint16_t userSize;
    uint16_t passwordSize;
    uint16_t domainSize;
    uint16_t shareSize;

    if (argc < 6) {
        puts("Too few arguments");
        return 0;
    }

    LoadOneTool(54, 0x200);
    TCPIPStartUp();
    
    TCPIPConvertIPCToHex(&theCvtRec, argv[1]);
    connectPB.serverIP = theCvtRec.cvtIPAddress;
    
    TCPIPConnect(NULL);

    FSTSpecific(&connectPB);
    if (toolerror()) {
        printf("connect error = %04x\n", toolerror());
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
    
    len = strlen(argv[5]);
    if (len > 100)
        len = 100;
    for (i = 0; i < len; i++) {
        share[i] = argv[5][i];
    }
    mountPB.shareName = share;
    mountPB.shareNameSize = len*2;

    FSTSpecific(&authenticatePB);
    if (toolerror()) {
        printf("authenticate error = %04x\n", toolerror());
        connectionReleasePB.connectionID = connectPB.connectionID;
        FSTSpecific(&connectionReleasePB);
        return 0;
    }

    connectionReleasePB.connectionID = connectPB.connectionID;
    FSTSpecific(&connectionReleasePB);

    mountPB.sessionID = authenticatePB.sessionID;
    FSTSpecific(&mountPB);

    if (!toolerror()) {
        printf("Mounted on device %u\n", mountPB.devNum);
    } else {
        printf("Error $%x\n", toolerror());
    }

    sessionReleasePB.sessionID = authenticatePB.sessionID;
    FSTSpecific(&sessionReleasePB);
    
    DInfo(&dInfoPB);
    Volume(&volumePB);
    if (toolerror()) {
        printf("VolumeGS error $%x\n", toolerror());
    
    } else {
        printf("Volume name = ");
        for (unsigned i = 0; i < volName.bufString.length; i++) {
            putchar(volName.bufString.text[i]);
        }
        printf("\n");
    }
}
