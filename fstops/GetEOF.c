/*
 * Copyright (c) 2024 Stephen Heumann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
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
