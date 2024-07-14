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
#include <memory.h>
#include "smb2/smb2.h"
#include "gsos/gsosdata.h"
#include "driver/driver.h"
#include "helpers/closerequest.h"

Word Close(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;
    VirtualPointer vp;
    FCR *fcr;
    VCR *vcr;
    unsigned i;
    
    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);

    vp = gsosdp->vcrPtr;
    DerefVP(vcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    if (fcr->dirCacheHandle != NULL) {
        DisposeHandle(fcr->dirCacheHandle);
        fcr->dirCacheHandle = NULL;
    }

    result = SendCloseRequestAndGetResponse(&dibs[i], &fcr->fileID);
    if (result != rsDone)
        return networkError;
    
    i = fcr->refNum;
    asm {
        ldx i
        phd
        lda gsosdp
        tcd
        txa
        jsl RELEASE_FCR
        pld
    }

    vcr->openCount--;
    
    return 0;
}
