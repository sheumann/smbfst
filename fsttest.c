#include <gsos.h>
#include <stdio.h>
#include <orca.h>
#include <stddef.h>
#include <tcpip.h>
#include <locator.h>

#include "fstspecific.h"

SMBConnectRec pblock = {
    .pCount = 7,
    .fileSysID = smbFSID,
    .commandNum = SMB_CONNECT,
    .serverIP = 0x79797979,
    .serverPort = 0,
    .serverName = NULL,
    .flags = 0x00FF,
};

int main(int argc, char *argv[]) {
    cvtRec theCvtRec;

    if (argc < 2)
        return 0;

    LoadOneTool(54, 0x200);
    TCPIPStartUp();
    
    TCPIPConvertIPCToHex(&theCvtRec, argv[1]);
    pblock.serverIP = theCvtRec.cvtIPAddress;
    
    TCPIPConnect(NULL);

    FSTSpecific(&pblock);
    printf("error = %04x\n", toolerror());
}