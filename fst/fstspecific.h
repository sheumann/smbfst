/*
 * Copyright (c) 2024 Stephen Heumann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef FSTSPECIFIC_H
#define FSTSPECIFIC_H

#include <types.h>
#include <uchar.h>
#include <stdint.h>

#define smbFSID 0x400e

#define SMB_CONNECT            0xC000
#define SMB_CONNECTION_RETAIN  0xC001
#define SMB_CONNECTION_RELEASE 0xC002
#define SMB_AUTHENTICATE       0xC003
#define SMB_SESSION_RETAIN     0xC004
#define SMB_SESSION_RELEASE    0xC005
#define SMB_MOUNT              0xC006

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
    Word flags; /* in/out */
    char16_t *userName;
    Word userNameSize;
    char16_t *userDomain;
    Word userDomainSize;
    char16_t *password;
    Word passwordSize;
    Byte ntlmv2Hash[16]; /* optional; in/out */
} SMBAuthenticateRec;

/* SMB_Authenticate flags bits */
#define AUTH_FLAG_GET_NTLMV2_HASH  0x0001
#define AUTH_FLAG_HAVE_NTLMV2_HASH 0x0002
#define AUTH_FLAG_ANONYMOUS        0x0004

typedef struct SMBConnectionRec {
    Word pCount;
    Word fileSysID;
    Word commandNum;
    LongWord connectionID;
} SMBConnectionRec;

typedef struct SMBSessionRec {
    Word pCount;
    Word fileSysID;
    Word commandNum;
    LongWord sessionID;
} SMBSessionRec;

typedef struct SMBMountRec {
    Word pCount;
    Word fileSysID;
    Word commandNum;
    LongWord sessionID;
    char16_t *shareName;
    uint16_t shareNameSize;
    Word devNum; /* out */
    GSString255 *volName;
} SMBMountRec;

#endif
