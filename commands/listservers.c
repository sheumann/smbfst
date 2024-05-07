#define GENERATE_ROOT
#include "defs.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <tcpip.h>
#include <misctool.h>
#include <memory.h>
#include <orca.h>
#include <shell.h>
#include "utils/endian.h"
#include "mdns/mdnsproto.h"
#include "mdns/mdnssd.h"

extern pascal int SysKeyAvail(void);

#define INITIAL_INTERVAL (1 * 60)  /* ticks */
#define MAX_INTERVAL     (16 * 60) /* ticks */

uint16_t interval = INITIAL_INTERVAL / 2;
uint32_t lastQueryTime = 0;

static uint8_t smbName[] = "\x04_smb\x04_tcp\x05local";

void PrintDNSName(const uint8_t *name) {
    uint16_t len;

    do {
        len = *name;
        if (len != 0)
            printf("%P.", name);
        name += len + 1;
    } while (len != 0);
}

void PrintServerInfo(ServerInfo *serverInfo) {
    printf("SMB server %P at ", serverInfo->name);
    
    PrintDNSName(serverInfo->hostName);
    
    printf(" (%u.%u.%u.%u), port %u\n",
        ((uint8_t*)&serverInfo->address)[0],
        ((uint8_t*)&serverInfo->address)[1],
        ((uint8_t*)&serverInfo->address)[2],
        ((uint8_t*)&serverInfo->address)[3],
        serverInfo->port);
}

int main(int argc, char *argv[]) {
    Handle dgmHandle;
    uint32_t mdnsIP = MDNS_IP;
    cvtRec theCvtRec;

    if (argc > 1) {
        TCPIPConvertIPCToHex(&theCvtRec, argv[1]);
        if (!toolerror()) {
            mdnsIP = theCvtRec.cvtIPAddress;
        }
     }

    Word ipid = TCPIPLogin(userid(), mdnsIP, MDNS_PORT, 0, 0x40);
    if (toolerror())
        return 0;
    
    MDNSInitQuery(smbName);

    while (!SysKeyAvail()) {
        if (GetTick() - lastQueryTime > interval) {
            MDNSSendQuery(ipid);
            lastQueryTime = GetTick();
            if (interval < MAX_INTERVAL)
                interval *= 2;
        }

        TCPIPPoll();
        dgmHandle = TCPIPGetNextDatagram(ipid, protocolUDP, 0xC000);
        if (!toolerror() && dgmHandle != NULL) {
            MDNSProcessPacket(dgmHandle, PrintServerInfo);
            DisposeHandle(dgmHandle);
        }
    }
}
