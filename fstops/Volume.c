#include "defs.h"
#include <string.h>
#include <gsos.h>
#include <prodos.h>
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "fst/fstspecific.h"
#include "helpers/blocks.h"

/*
 * Fake block count that we return for all volumes.
 */
// TODO maybe return real information (need to deal with overflows)
#define TOTAL_BLOCKS 0x7fffff
#define FREE_BLOCKS  0x7fffff

Word Volume(void *pblock, struct GSOSDP *gsosDP, Word pcount) {
    unsigned i;
    GSString *volName;
    GSString *pathName;
    Word result = 0;

    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    volName = dibs[i].volName;

    if (volName->length > GBUF_SIZE - 3) {
        // This should not happen in practice
        pathName = NULL;
    } else {
        pathName = (void*)gbuf;
        pathName->length = volName->length + 1;
        pathName->text[0] = (pcount == 0 ? '/' : ':');
        memcpy(pathName->text+1, volName->text, volName->length);
    }

    if (pcount == 0) {
        #define pblock ((VolumeRec*)pblock)
        
        // TODO maybe restrict to shorter length (16 chars, like for ProDOS?)
        if (pathName == NULL ||
            WritePString(pathName->length, pathName->text, pblock->volName))
        {
            result = buffTooSmall;
        }

        pblock->totalBlocks = TOTAL_BLOCKS;
        pblock->freeBlocks = FREE_BLOCKS;
        pblock->fileSysID = smbFSID;
        
        #undef pblock
    } else {
        #define pblock ((VolumeRecGS*)pblock)

        if (pathName == NULL ||
            WriteGSOSString(pathName->length, pathName->text, pblock->volName))
        {
            result = buffTooSmall;
        }
        
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
