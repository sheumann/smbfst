#include "defs.h"
#include <stdlib.h>
#include <errno.h>
#include <tcpip.h>
#include <gsos.h>
#include <orca.h>
#include "fst/fstspecific.h"
#include "cdev/errorcodes.h"

#define SMB_PORT 445

static SMBConnectRec connectPB = {
    .pCount = 7,
    .fileSysID = smbFSID,
    .commandNum = SMB_CONNECT,
    .serverIP = 0,
    .serverPort = 0,
    .serverName = NULL,
    .flags = 0x00FF,
};

unsigned ConnectToSMBServer(char *host, char *port, LongWord *connectionID) {
    char *endPtr;
    cvtRec theCvtRec;
    unsigned long portNum;

    // TODO handle domain names
    TCPIPConvertIPCToHex(&theCvtRec, host);
    connectPB.serverIP = theCvtRec.cvtIPAddress;

    if (port) {
        errno = 0;
        portNum = strtoul(port, &endPtr, 10);
        if (errno != 0 || *endPtr != '\0' || portNum > 0xFFFF) {
            // TODO report error
            return badPortNumberError;
        }
        connectPB.serverPort = portNum;
    } else {
        connectPB.serverPort = SMB_PORT;
    }
    
    TCPIPConnect(NULL);
    if (toolerror() && toolerror() != terrCONNECTED) {
        return connectTCPIPError;
    }

    FSTSpecific(&connectPB);
    if (toolerror()) {
        return connectToServerError;
    }
    
    *connectionID = connectPB.connectionID;
    return 0;
}