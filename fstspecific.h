#include <types.h>

#define smbFSID 0x800e

#define SMB_CONNECT 0

typedef struct SMBConnectRec {
    Word pCount;
    Word fileSysID;
    Word commandNum;
    LongWord serverIP;
    LongWord serverPort;
    char *serverName;
    Word flags;
    LongWord connectionID; /* out */
} SMBConnectRec;
