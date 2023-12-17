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

int main(int argc, char *argv[]) {
    cvtRec theCvtRec;
    
    size_t len;
    unsigned i;

    static char16_t user[100];
    static char16_t password[100];
    static char16_t domain[100];
    uint16_t userSize;
    uint16_t passwordSize;
    uint16_t domainSize;

    if (argc < 4) {
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

    FSTSpecific(&authenticatePB);
    if (toolerror()) {
        printf("authenticate error = %04x\n", toolerror());
    }
}