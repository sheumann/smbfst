#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <stddef.h>
#include "smb2.h"
#include "fileinfo.h"
#include "gsosdata.h"
#include "driver.h"
#include "helpers/position.h"
#include "helpers/errors.h"

Word SetMark(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    VirtualPointer vp;
    FCR *fcr;
    unsigned i;
    Word retval = 0;

    uint64_t pos, eof;
    Word base;
    uint32_t displacement;

    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num /* TODO && active */)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    if (pcount == 0) {
        #define pblock ((MarkRec*)pblock)

        base = startPlus;
        displacement = pblock->position;

        #undef pblock
    } else {
        #define pblock ((SetPositionRecGS*)pblock)
        
        base = pblock->base;
        displacement = pblock->displacement;
        
        #undef pblock
    }
    
    retval = CalcPosition(fcr, &dibs[i], base, displacement, &pos, &eof);
    if (retval != 0)
        return retval;

    if (pos > eof)
        return outOfRange;

    fcr->mark = pos;

    return retval;
}
