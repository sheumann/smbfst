#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include "gsosdata.h"

Word GetMark(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    VirtualPointer vp;
    FCR *fcr;
    uint32_t mark;
    Word retval = 0;
    
    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);
    
    if (fcr->mark > 0xFFFFFFFF) {
        mark = 0xFFFFFFFF;
        retval = outOfRange;
    } else {
        mark = fcr->mark;
    }

    if (pcount == 0) {
        #define pblock ((MarkRec*)pblock)
        pblock->position = mark;
        #undef pblock
    } else {
        #define pblock ((PositionRecGS*)pblock)
        pblock->position = mark;
        #undef pblock
    }
    
    return retval;
}
