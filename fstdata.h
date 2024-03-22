#ifndef __FSTDATA_H__
#define __FSTDATA_H__

#include <types.h>

/* GS/OS string and result buf types.
 *
 * These are not really limited to 255 characters.  That's just how the
 * structures are specified in the C headers.
 */
typedef ResultBuf255 ResultBuf;
typedef ResultBuf255Ptr ResultBufPtr;
typedef GSString255 GSString;
typedef GSString255Ptr GSStringPtr;

#define GBUF_SIZE 1024

/* System service calls */
#define ALLOC_VCR 0x01fc24
#define DEREF     0x01fc38
#define FIND_VCR  0x01fc48

/* GS/OS direct page structure */
struct GSOSDP {
    /* Data used in device driver calls */
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
    
    /* Additional internal data */
    void *devPtr;
    union {
        void *genDrvPtr;
        void *fwAddr;
    };
    void *fileListPtr;
    
    /* Data used in FST calls */
    Word callNumber;
    void *paramBlockPtr;
    union {
        Word devNum;
        Word dev1Num;
    };
    Word dev2Num;
    union {
        GSString *path1Ptr;
        void *fcrPtr;
    };
    union {
        GSString *path2Ptr;
        void *vcrPtr;
    };
    Word pathFlag;
    Word span1;
    Word span2;
    
};

/* pathFlag bits */
#define HAVE_PATH1 0x4000
#define HAVE_PATH2 0x0040

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

#define DerefVP(ptr,vp) \
    do {                            \
        *(LongWord*)&(ptr) = (vp);  \
        asm { ldx ptr }             \
        asm { ldy ptr+2 }           \
        asm { phd }                 \
        asm { lda gsosDP }          \
        asm { tcd }                 \
        asm { jsl DEREF }           \
        asm { pld }                 \
        asm { stx ptr }             \
        asm { sty ptr+2 }           \
    } while (0)

#endif
