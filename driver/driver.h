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

#ifndef DRIVER_H
#define DRIVER_H

#include <stdbool.h>
#include <types.h>
#include "gsos/gsosdata.h"
#include "smb2/session.h"
#include "driver/dib.h"

#define DEVICE_FILE_SERVER 0x0010

/* device information block */
struct DIB {
    void *linkPtr;
    void *entryPtr;
    Word characteristics;
    LongWord blockCount;
    char devName[32];
    Word slotNum;
    Word unitNum;
    Word version;
    Word deviceID;
    Word headlink;
    Word forwardLink;
    void *extendedDIBPtr;
    Word DIBDevNum;
    
    // SMB-specific part
    LongWord treeId;
    bool switched;
    Session *session;
    Word flags;
    char16_t *shareName;
    uint16_t shareNameSize;
    GSString *volName;
    
    // ID number that is unique for each "different" tree connect.
    // (Reconnects do not get a new ID number.)
    uint32_t treeConnectID;
};

/* flags bits */
#define FLAG_AAPL_READDIR 0x0001
#define FLAG_READONLY     0x0002
#define FLAG_PIPE_SHARE   0x0004
#define FLAG_MACOS        0x0008

/* list of DIBs (argument to INSTALL_DRIVER) */
struct DIBList {
    LongWord count;
    struct DIB *dibPointers[NDIBS];
};

/* GS/OS driver call numbers */
#define Driver_Startup  0x0000
#define Driver_Open     0x0001
#define Driver_Read     0x0002
#define Driver_Write    0x0003
#define Driver_Close    0x0004
#define Driver_Status   0x0005
#define Driver_Control  0x0006
#define Driver_Flush    0x0007
#define Driver_Shutdown 0x0008

/* Driver_Status subcalls */
#define Get_Device_Status     0x0000
#define Get_Config_Parameters 0x0001
#define Get_Wait_Status       0x0002
#define Get_Format_Options    0x0003
#define Get_Partition_Map     0x0004


/* Status list record for Get_DeviceStatus */
typedef struct DeviceStatusRec {
    Word statusWord;
    LongWord numBlocks;
} DeviceStatusRec;

extern struct DIB dibs[NDIBS];
extern struct DIBList dibList;

void InitDIBs(void);
Word DriverDispatch(Word callNum, struct GSOSDP *dp);
void UnmountSMBVolume(DIB *dib);

#endif
