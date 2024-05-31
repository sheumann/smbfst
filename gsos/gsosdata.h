#ifndef GSOSDATA_H
#define GSOSDATA_H

#include <types.h>
#include <stdint.h>
#include "smb2/smb2proto.h"
#include "driver/dib.h"

/*
 * GS/OS string and result buf types.
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
#define ALLOC_VCR   0x01fc24
#define DEREF       0x01fc38
#define FIND_VCR    0x01fc48
#define ALLOC_FCR   0x01fc2c
#define RELEASE_FCR 0x01fc30
#define GET_FCR     0x01fc64
#define RELEASE_VCR 0x01fc28
#define SET_DISKSW  0x01fc90
#define SWAP_OUT    0x01fc34

typedef LongWord VirtualPointer;

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
        VirtualPointer fcrPtr;
    };
    union {
        GSString *path2Ptr;
        VirtualPointer vcrPtr;
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
    VirtualPointer name; /* virtual pointer to volume name */
    Word status;
    Word openCount;
    Word fstID;
    Word devNum;
    void *fstPtr;
    
    /* SMB-specific fields go here */
    DIB *dib;
    uint32_t treeConnectID;
} VCR;

typedef struct FCR {
    Word refNum;
    VirtualPointer pathName;
    Word fstID;
    Word volID;
    Word level;
    VirtualPointer newline;
    Word newlineLen;
    Word mask;
    Word access;
    
    /* SMB-specific fields go here */
    SMB2_FILEID fileID;
    uint64_t mark;
    
    // number of last dir entry fetched by a GetDirEntry call
    uint16_t dirEntryNum;
    
    // number of next dir entry that would be fetched from server
    // (. and .. are considered entries -1 and 0; GDE returns entries 1 onward)
    int32_t nextServerEntryNum; 

    // Handle holding cached directory entires
    Handle dirCacheHandle;

    /* These fields are only valid if dirCacheHandle != NULL */
    // First entry in the cache
    int32_t firstCachedEntryNum;
    // Last used entry in the cache
    uint16_t lastUsedCachedEntryNum;
    // Offset of last used entry within cached data
    uint16_t lastUsedCachedEntryOffset;
    
    uint16_t smbFlags;
    uint64_t createTime;
    
    // Our local cached copy of the EOF.  This is only used to avoid
    // going to the server to check if a SetMark call would go past EOF,
    // and is otherwise not treated as authoritative.
    uint64_t eof;
} FCR;

/* access bits (in addition to standard access flags in low bits) */
#define ACCESS_FLAG_CLEAN 0x8000
#define ACCESS_FLAG_RFORK 0x4000

#define SMB_FLAG_P16SHARING 0x0001

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
