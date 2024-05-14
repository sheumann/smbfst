#include "defs.h"
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <gsos.h>
#include <intmath.h>
#include "driver/driver.h"
#include "smb2/smb2.h"
#include "utils/alloc.h"

#define DRIVER_VERSION 0x001E             /* GS/OS driver version format */

struct DIB dibs[NDIBS] = {0};
struct DIBList dibList = {NDIBS};

static asm void DriverWrapper(void);

static Word DoStatus(struct GSOSDP *dp);
static Word DoEject(struct GSOSDP *dp);
static Word DoShutdown(struct GSOSDP *dp);

// length of number as a decimal string (assumes it is less than 100)
#define numlen(x) ((x) >= 10 ? 2 : 1)

void InitDIBs(void) {
    for (unsigned i = 0; i < NDIBS; i++) {
        dibs[i].linkPtr = (i < NDIBS-1) ? &dibs[i+1] : NULL;
        dibs[i].entryPtr = DriverWrapper;
            /* speed-independent, block device, read/write allowed, removable */
        dibs[i].characteristics = 0x03E4;
        dibs[i].blockCount = 0;
        
        memcpy(&dibs[i].devName[1], "SMB", 3);
        Int2Dec(i+1, &dibs[i].devName[4], numlen(i+1), FALSE);
        int nameLen = 3 + numlen(i+1);
        dibs[i].devName[0] = nameLen;
        for (unsigned j = nameLen + 1; j < sizeof(dibs[i].devName); j++) {
            dibs[i].devName[j] = ' ';
        }
        
        dibs[i].slotNum = 0x8003;
        dibs[i].unitNum = i+1;
        dibs[i].version = DRIVER_VERSION;
        dibs[i].deviceID = DEVICE_FILE_SERVER;
        
        dibList.dibPointers[i] = &dibs[i];
    }

}

static asm void DriverWrapper(void) {
    pea 0               // direct page pointer
    phd
    
    pha                 // call number
    
    jsl DriverDispatch
    cmp #1              // set carry based on return value
    rtl
}

#pragma databank 1
Word DriverDispatch(Word callNum, struct GSOSDP *dp) {
    Word retVal = 0;

    switch (callNum) {
    case Driver_Startup:
        gsosDP = dp;
        break;
    
    case Driver_Open:
    case Driver_Close:
        /* Only applicable to character devices, but no error for block devs */
        break;
        
    case Driver_Read:
        dp->transferCount = 0;
        if (dp->dibPointer->switched) {
            retVal = drvrDiskSwitch;
            dp->dibPointer->switched = false;
        } else if (dp->dibPointer->extendedDIBPtr == NULL) {
            retVal = drvrOffLine;
        } else if (dp->requestCount == 0) {
            /* 0-byte reads are considered OK */
        } else {
            retVal = networkError;
        }
        break;

    case Driver_Write:
        dp->transferCount = 0;
        retVal = drvrWrtProt;
        break;
        
    case Driver_Status:
        switch (dp->statusCode) {
        case Get_Device_Status:
            retVal = DoStatus(dp);
            break;
            
        case Get_Config_Parameters:
            if (dp->requestCount < 2) {
                dp->transferCount = 0;
                retVal = drvrBadParm;
                break;
            }
            /* config list has length 0 */
            *(Word*)dp->statusListPtr = 0;
            dp->transferCount = 2;
            break;
            
        case Get_Wait_Status:
            if (dp->requestCount != 2) {
                dp->transferCount = 0;
                retVal = drvrBadParm;
                break;
            }
            /* always in wait mode */
            *(Word*)dp->statusListPtr = 0;
            dp->transferCount = 2;
            break;
            
        case Get_Format_Options:
            /* no format options */
            dp->transferCount = 0;
            break;
            
        case Get_Partition_Map:
            /* no partition map */
            dp->transferCount = 0;
            break;
        
        default:
            dp->transferCount = 0;
            retVal = drvrBadCode;
            break;
        }
        break;
        
    case Driver_Control:
        switch (dp->controlCode) {
        case eject:
            retVal = DoEject(dp);
            break;
            
        case setConfigParameters:
            dp->transferCount = 0;
            if (dp->requestCount < 2) {
                retVal = drvrBadParm;
                break;
            }
            /* config list should be empty (zero length) */
            if (*(Word*)dp->controlListPtr != 0) {
                retVal = drvrBadParm;
                break;
            }
            break;
            
        case setWaitStatus:
            dp->transferCount = 0;
            if (dp->requestCount != 2) {
                retVal = drvrBadParm;
                break;
            }
            /* only wait mode is valid */
            if (*(Word*)dp->controlListPtr != 0) {
                retVal = drvrBadParm;
                break;
            }
            break;
            
        case resetDevice:
        case formatDevice:
        case setFormatOptions:
        case assignPartitionOwner:
        case armSignal:
        case disarmSignal:
        case setPartitionMap:
            /* do nothing, and return no error */
            dp->transferCount = 0;
            break;
        
        default:
            dp->transferCount = 0;
            retVal = drvrBadCode;
            break;
        }
        break;
        
    case Driver_Flush:
        /* Only applicable to character devices; error for block devices */
        retVal = drvrBadReq;
        break;
    
    case Driver_Shutdown:
        retVal = DoShutdown(dp);
        break;
    
    default:
        retVal = drvrBadReq;
        break;
    }

    return retVal;
}
#pragma databank 0

/* This implements the Get_Device_Status subcall of Driver_Status */
static Word DoStatus(struct GSOSDP *dp) {
    DeviceStatusRec *dsRec = (DeviceStatusRec*)dp->statusListPtr;

    if (dp->requestCount < 2) {
        dp->transferCount = 0;
        return drvrBadParm;
    }
    //TODO disk-switched logic
    if (dp->dibPointer->extendedDIBPtr != NULL) {
        dsRec->statusWord = 0x0010;
        if (dp->dibPointer->flags & FLAG_READONLY)
            dsRec->statusWord |= 0x0004;
    } else {
        dsRec->statusWord = 0;
    }
    if (dp->requestCount < 6) {
        dp->transferCount = 2;
        return 0;
    }
    dsRec->numBlocks = dp->dibPointer->blockCount;
    if (dsRec->numBlocks == 0) {
        dsRec->statusWord |= 0x8000;
    }
    dp->transferCount = 6;
    return 0;
}

void UnmountSMBVolume(DIB *dib) {
    if (dib->extendedDIBPtr != NULL) {
        treeDisconnectRequest.Reserved = 0;
        SendRequestAndGetResponse(dib, SMB2_TREE_DISCONNECT,
            sizeof(treeDisconnectRequest));
        // ignore errors from tree disconnect

        Session_Release(dib->session);
        dib->session = NULL;
        dib->treeId = 0;
        dib->switched = true;
        dib->flags = 0;
        dib->extendedDIBPtr = NULL;
        smb_free(dib->shareName);
        dib->shareName = NULL;
        dib->shareNameSize = 0;
        smb_free(dib->volName);
        dib->volName = NULL;
    }
}

static Word DoEject(struct GSOSDP *dp) {
    UnmountSMBVolume(dp->dibPointer);
    dp->transferCount = 0;
    return 0;
}

static Word DoShutdown(struct GSOSDP *dp) {
    /*
     * Return error to indicate we shouldn't be purged.
     * (I don't think we would be anyhow, since this isn't an
     * actual device driver file, but let's do this to be safe.)
     */
    return drvrIOError;
}
