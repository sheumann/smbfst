#ifndef __FSTDATA_H__
#define __FSTDATA_H__

#include <types.h>

#define GBUF_SIZE 1024

/* System service calls */
#define ALLOC_VCR 0x01fc24
#define DEREF     0x01fc38

/* GS/OS direct page structure */
struct GSOSDP {
    Word deviceNum;
    Word callNum;
    union {
        Byte *bufferPtr;
        Byte *statusListPtr;
        Byte *controlListPtr;
    };
    LongWord requestCount;
    LongWord transferCount;
    LongWord blockNum;
    Word blockSize;
    union {
        Word fstNum;
        Word statusCode;
        Word controlCode;
    };
    Word volumeID;
    Word cachePriority;
    void *cachePointer;
    struct DIB *dibPointer;
};

typedef struct VCR {
    Word id;
    LongWord name; /* virtual pointer to volume name */
    Word status;
    Word openCount;
    Word fstID;
    Word devNum;
    void *fstPtr;
    
    /* SMB-specific fields would go here */
} VCR;

extern unsigned char *gbuf;
extern struct GSOSDP *gsosDP;  /* GS/OS direct page ptr */

#endif
