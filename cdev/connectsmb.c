#define USE_BLANK_SEG
#include "defs.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <tcpip.h>
#include <gsos.h>
#include <orca.h>
#include "fst/fstspecific.h"
#include "cdev/errorcodes.h"
#include "cdev/strncasecmp.h"
#include "mdns/mdns.h"

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

/*
 * Connect to an SMB server at the specified host and port.
 * If ipAddress is not 0, it is used; otherwise the address is resolved from the
 * specified hostname.  On success, *connectionID is set to the connection ID.
 *
 * Returns an error code, or 0 on success.
 * 
 */
unsigned ConnectToSMBServer(char *host, char *port, LongWord ipAddress,
    LongWord *connectionID) {
    char *endPtr;
    cvtRec theCvtRec;
    unsigned long portNum;
    static char hostPstring[256];
    static dnrBuffer dnrState;
    size_t hostLen;

    if (ipAddress != 0) {
        connectPB.serverIP = ipAddress;
    } else if (TCPIPValidateIPCString(host)) {
        TCPIPConvertIPCToHex(&theCvtRec, host);
        connectPB.serverIP = theCvtRec.cvtIPAddress;
    } else if ((hostLen = strlen(host)) <= 255) {
        if ((hostLen >= 6 && !strncasecmp(host + hostLen - 6, ".local", 6))
            || (hostLen >= 7 && !strncasecmp(host + hostLen - 7, ".local.", 7))) {
            connectPB.serverIP = MDNSResolveName(host);
            if (connectPB.serverIP == 0)
                return connectToServerError;
        } else {
            hostPstring[0] = strlen(host);
            memcpy(hostPstring+1, host, hostPstring[0]);
            TCPIPDNRNameToIP(hostPstring, &dnrState);
            do {
                TCPIPPoll();
            } while (dnrState.DNRstatus == DNR_Pending);
            
            if (dnrState.DNRstatus == DNR_OK) {
                connectPB.serverIP = dnrState.DNRIPaddress;
            } else {
                return connectToServerError;
            }
        }
    } else {
        return connectToServerError;
    }

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