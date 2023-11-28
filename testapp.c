#include <stdio.h>
#include <stddef.h>
#include <orca.h>

#include <tcpip.h>
#include <locator.h>
#include <misctool.h>

#include "defs.h"
#include "smb2proto.h"
#include "connection.h"
#include "smb2.h"

#define TIMEOUT 15 /* seconds */

int main(int argc, char *argv[]) {
        Word tcpError;
        Long serverIP;
        cvtRec theCvtRec;
        srBuff status;
        Long startTime;
        Connection connection = {0};
        
        if (argc < 2) {
            puts("Too few arguments");
            goto args_error;
        }

        LoadOneTool(54, 0x200);
        TCPIPStartUp();
        
        TCPIPConvertIPCToHex(&theCvtRec, argv[1]);
        serverIP = theCvtRec.cvtIPAddress;
        
        TCPIPConnect(NULL);
        
        connection.ipid = TCPIPLogin(userid(), serverIP, SMB_PORT, 0, 64);
        if (toolerror()) {
            puts("login error");
            goto login_error;
        }
        
        printf("ipid = %u\n", connection.ipid);
        
        tcpError = TCPIPOpenTCP(connection.ipid);
        if (tcpError || toolerror()) {
            puts("open error");
            goto open_error;
        }
        
        startTime = GetTick();
        do {
            TCPIPPoll();
            TCPIPStatusTCP(connection.ipid, &status);
        } while (
            status.srState != TCPSESTABLISHED && status.srState != TCPSCLOSED
            && GetTick() - startTime < TIMEOUT * 60);
        
        if (status.srState != TCPSESTABLISHED) {
            puts("connection failed");
            goto connect_error;
        }

        puts("connected");
        
        Negotiate(&connection);
        
        puts("ending");
        
connect_error:
        TCPIPAbortTCP(connection.ipid);
        
open_error:
        TCPIPLogout(connection.ipid);
        
login_error:
        TCPIPShutDown();

args_error:
        ;
}
