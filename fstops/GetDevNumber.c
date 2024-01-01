#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include "fstdata.h"

Word GetDevNumber(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    if (gsosdp->dev1Num == 0) {
        // TODO is there a success case where we need to look up the dev num?
        // TODO adjust error based on type of path (device or volume name?)
        return devNotFound;
    }
    
    if (pcount == 0) {
        #define pblock ((DevNumRec*)pblock)
        
        pblock->devNum = gsosdp->dev1Num;
        
        #undef pblock
    } else {
        #define pblock ((DevNumRecGS*)pblock)
        
        pblock->devNum = gsosdp->dev1Num;
        
        #undef pblock
    }

    return 0;
}
