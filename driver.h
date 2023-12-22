#ifndef __DRIVER_H__
#define __DRIVER_H__

#include <stdbool.h>
#include <types.h>
#include "fstdata.h"

#define DEVICE_FILE_SERVER 0x0010

#define NDIBS 16

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
};

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

#endif
