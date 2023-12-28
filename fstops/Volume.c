#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include "driver.h"
#include "gsosutils.h"
#include "fstspecific.h"

/*
 * Fake block size/block count information that we return for all volumes.
 */
// TODO maybe return real information (need to deal with overflows)
#define TOTAL_BLOCKS 0x7fffff
#define FREE_BLOCKS  0x7fffff
#define BLOCK_SIZE   0x000100

Word Volume(void *pblock, struct GSOSDP *gsosDP, Word pcount) {
    unsigned i;
    VCR *vcr;
    char *volName;
    Word result = 0;

    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num /* TODO && active */)
            break;
    }
    if (i == NDIBS)
        return volNotFound;
    
    DerefVP(vcr, dibs[i].vcrVP);
    DerefVP(volName, vcr->name);
    
    if (pcount == 0) {
        #define pblock ((VolumeRec*)pblock)
        
        if (WritePString(volName[0], volName+1, pblock->volName))
            result = buffTooSmall;

        pblock->totalBlocks = TOTAL_BLOCKS;
        pblock->freeBlocks = FREE_BLOCKS;
        pblock->fileSysID = smbFSID;
        
        #undef pblock
    } else {
        #define pblock ((VolumeRecGS*)pblock)

        if (WriteGSOSString(volName[0], volName+1, pblock->volName))
            result = buffTooSmall;
        
        if (pcount < 3) goto end;
        pblock->totalBlocks = TOTAL_BLOCKS;
        
        if (pcount < 4) goto end;
        pblock->freeBlocks = FREE_BLOCKS;

        if (pcount < 5) goto end;
        pblock->fileSysID = smbFSID;
        
        if (pcount < 6) goto end;
        pblock->blockSize = BLOCK_SIZE;
        
        /* Note: GS/OS sets characteristics and deviceID, if necessary */
        
        #undef pblock
    }

end:
    return result;
}
