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
#include "helpers/errors.h"

/*
 * Flush pblock, including optional flush type as second parameter.
 * (Added in System 5.0.3; see System 5.0.4 release notes.)
 */
typedef struct FlushRecGS {
    Word pCount;
    Word refNum;
    Word flushType;
} FlushRecGS, *FlushRecPtrGS;

// flush type for a fast flush, not necessarily updating access time
#define fastFlush 0x8000

Word Flush(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;
    VirtualPointer vp;
    FCR *fcr;
    unsigned i;

    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    if (pcount == 2) {
        /*
         * Validate flush type, if present.
         * Other than this, we don't do anything special for a "fast" flush.
         */
        if ((((FlushRecGS*)pblock)->flushType & ~fastFlush) != 0)
            return paramRangeErr;
    }    

    flushRequest.Reserved1 = 0;
    flushRequest.Reserved2 = 0;
    flushRequest.FileId = fcr->fileID;
    
    result = SendRequestAndGetResponse(&dibs[i], SMB2_FLUSH,
        sizeof(flushRequest));
    if (result != rsDone)
        return ConvertError(result);
    
    return 0;
}
