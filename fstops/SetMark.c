#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <stddef.h>
#include "smb2/smb2.h"
#include "smb2/fileinfo.h"
#include "gsos/gsosdata.h"
#include "driver/driver.h"
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
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
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
    
    retval = CalcPosition(fcr, &dibs[i], base, displacement, &pos);
    if (retval != 0)
        return retval;

    /*
     * Check for position past our cached copy of EOF.  If it appears to be
     * past EOF, confirm EOF with server before reporting an error.
     */
    if (pos > fcr->eof) {
        retval = GetEndOfFile(fcr, &dibs[i], &eof);
        if (retval != 0)
            return retval;
        if (pos > eof)
            return outOfRange;
    }

    fcr->mark = pos;

    return retval;
}
