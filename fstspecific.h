#ifndef __FSTSPECIFIC_H__
#define __FSTSPECIFIC_H__

#include <types.h>
#include <uchar.h>

#define smbFSID 0x800e

#define SMB_CONNECT 0
#define SMB_AUTHENTICATE 1

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

typedef struct SMBAuthenticateRec {
    Word pCount;
    Word fileSysID;
    Word commandNum;
    LongWord connectionID;
    LongWord sessionID; /* out */
    Word flags;
    char16_t *userName;
    Word userNameSize;
    char16_t *userDomain;
    Word userDomainSize;
    char16_t *password;
    Word passwordSize;
} SMBAuthenticateRec;

#endif
