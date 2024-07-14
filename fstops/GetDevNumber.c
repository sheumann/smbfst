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
#include "gsos/gsosdata.h"
#include "driver/driver.h"
#include "gsos/gsosutils.h"

Word GetDevNumber(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word devNum = gsosdp->dev1Num;
    
    if (devNum == 0) {
        DIB *dib = GetDIB(gsosdp, 1);
        if (dib == NULL) {
            // TODO adjust error based on type of path (device or volume name?)
            return devNotFound;
        }
        devNum = dib->DIBDevNum;
    }
    
    if (pcount == 0) {
        #define pblock ((DevNumRec*)pblock)
        
        pblock->devNum = devNum;
        
        #undef pblock
    } else {
        #define pblock ((DevNumRecGS*)pblock)
        
        pblock->devNum = devNum;
        
        #undef pblock
    }

    return 0;
}
