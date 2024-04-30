#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include "smb2/smb2.h"
#include "gsos/gsosdata.h"
#include "driver/driver.h"
#include "smb2/fileinfo.h"
#include "helpers/errors.h"
#include "helpers/position.h"

Word GetEOF(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    VirtualPointer vp;
    FCR *fcr;
    unsigned i;
    uint64_t eof;
    Word retval = 0;
    
    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num /* TODO && active */)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    retval = GetEndOfFile(fcr, &dibs[i], &eof);
    if (retval != 0)
        return retval;

    if (eof > 0xFFFFFFFF) {
        eof = 0xFFFFFFFF;
        retval = outOfRange;
    }

    if (pcount == 0) {
        #define pblock ((EOFRec*)pblock)
        pblock->eofPosition = eof;
        #undef pblock
    } else {
        #define pblock ((EOFRecGS*)pblock)
        pblock->eof = eof;
        #undef pblock
    }
    
    return retval;
}
