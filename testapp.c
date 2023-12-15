#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <uchar.h>
#include <orca.h>

#include <tcpip.h>
#include <locator.h>
#include <misctool.h>

#define GENERATE_ROOT
#include "defs.h"
#include "smb2proto.h"
#include "connection.h"
#include "smb2.h"
#include "authinfo.h"
#include "fileinfo.h"

#define TIMEOUT 15 /* seconds */

int main(int argc, char *argv[]) {
        Word tcpError;
        Long serverIP;
        cvtRec theCvtRec;
        srBuff status;
        Long startTime;
        Connection connection = {0};
        int i,j;
        size_t len;
        uint32_t treeId;
        SMB2_FILEID fileId;

        static char16_t treeName[100];
        static uint16_t treeNameSize;
        
        static char16_t fileName[100];
        static uint16_t fileNameSize;
        
        static uint8_t buf[1000];
        uint32_t readSize;
        
        if (argc < 4) {
            puts("Too few arguments");
            goto args_error;
        }

        len = strlen(argv[2]);
        if (len > 100)
            len = 100;
        for (i = 0; i < len; i++) {
            user[i] = argv[2][i];
            userUpperCase[i] = toupper(argv[2][i]);
        }
        userSize = len*2;

        len = strlen(argv[3]);
        if (len > 100)
            len = 100;
        for (i = 0; i < len; i++) {
            password[i] = argv[3][i];
        }
        passwordSize = len*2;
        
        if (argc >= 5) {
            len = strlen(argv[4]);
            if (len > 100)
                len = 100;
            for (i = 0; i < len; i++) {
                userDomain[i] = argv[4][i];
            }
            userDomainSize = len*2;
        }

        if (argc >= 6) {
            // TODO length check
            i = 0;
            treeName[i++] = '\\';
            treeName[i++] = '\\';
            
            len = strlen(argv[1]);
            for (j = 0; j < len; i++, j++) {
                treeName[i] = argv[1][j];
            }

            treeName[i++] = '\\';

            len = strlen(argv[5]);
            for (j = 0; j < len; i++, j++) {
                treeName[i] = argv[5][j];
            }
            
            treeNameSize = i*2;
        }

        if (argc >= 7) {
            len = strlen(argv[6]);
            if (len > 100)
                len = 100;
            for (i = 0; i < len; i++) {
                fileName[i] = argv[6][i];
            }
            fileNameSize = len*2;
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
        
        SessionSetup(&connection);
        
        if (argc >= 6)
            treeId = TreeConnect(&connection, treeName, treeNameSize);
        
        if (argc >= 7) {
            fileId = Open(&connection, treeId, fileName, fileNameSize);
            readSize = Read(&connection, treeId, fileId, 0, 1000, buf);
            
            printf("data read:\n");
            for (unsigned i = 0; i < readSize; i++) {
                putchar(buf[i]);
            }
            printf("\n");
            
            Close(&connection, treeId, fileId);
        }
        
        if (argc > 6) {
            fileId = Open(&connection, treeId, NULL, 0); // root dir of share

            printf("Directory listing:\n");
            do {
                uint16_t entrySize = QueryDirectory(
                    &connection, treeId, fileId, sizeof(buf), buf);
                if (entrySize == 0)
                    break;
                   
                FILE_DIRECTORY_INFORMATION *dirInfo = (void*)&buf;
                uint16_t nameSize = dirInfo->FileNameLength / 2;
                //TODO validate that name does not overflow buffer
                
                for (unsigned i = 0; i < nameSize; i++) {
                    putchar(dirInfo->FileName[i]);
                }
                putchar('\n');
            } while (1);
            
            Close(&connection, treeId, fileId);
        }
        
connect_error:
        TCPIPAbortTCP(connection.ipid);
        
open_error:
        TCPIPLogout(connection.ipid);
        
login_error:
        TCPIPShutDown();

args_error:
        ;
}
