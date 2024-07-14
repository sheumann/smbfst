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
#include <stdbool.h>
#include <gsos.h>
#include <string.h>
#include "gsos/gsosutils.h"
#include "utils/memcasecmp.h"

Word WriteGSOSString(Word length, char *str, ResultBufPtr buf) {
    char *outStr;
    Word i;

    if (buf->bufSize < 4)
        return buffTooSmall;

    buf->bufString.length = length;

    if (buf->bufSize - 2 < length)
        return buffTooSmall;
    
    outStr = buf->bufString.text;
    for (i = 0; i < length; i++) {
        outStr[i] = str[i];
    }
    return 0;
}

Word WritePString(Word length, char *str, char *buf) {
    Word i;

    // TODO check how we should handle string-too-long case (maybe truncate?)
    if (length > 255)
        return buffTooSmall;

    buf[0] = length;
    for (i = 0; i < length; i++) {
        buf[i+1] = str[i];
    }
    return 0;
}

/* Get device number for call from GS/OS DP (path 1 or 2). */
DIB *GetDIB(struct GSOSDP *gsosdp, int num) {
    Word devNum;
    GSString *path;
    size_t volNameLen;
    unsigned i;
    char *sep;

    if ((num == 1 && (gsosdp->pathFlag & HAVE_PATH1)) ||
        (num == 2 && (gsosdp->pathFlag & HAVE_PATH2))) {
        if (num == 1) {
            path = gsosdp->path1Ptr;
        } else {
            path = gsosdp->path2Ptr;
        }

        if (path->length == 0)
            return NULL;
        if (path->text[0] != ':')
            goto useDevNum;

        sep = memchr(path->text+1, ':', path->length-1);
        if (sep) {
            volNameLen = sep - path->text - 1;
        } else {
            volNameLen = path->length - 1;
        }

        for (i = 0; i < NDIBS; i++) {
            if (dibs[i].extendedDIBPtr != 0
                && dibs[i].volName->length == volNameLen
                && memcasecmp(dibs[i].volName->text, path->text+1, volNameLen)
                    == 0)
                return &dibs[i];
        }
    } else {
useDevNum:
        if (num == 1) {
            devNum = gsosdp->dev1Num;
        } else {
            devNum = gsosdp->dev2Num;
        }
    
        for (i = 0; i < NDIBS; i++) {
            if (dibs[i].DIBDevNum == devNum  && dibs[i].extendedDIBPtr != 0)
                return &dibs[i];
        }
    }

    return NULL;
}

/*
 * Get VCR for the SMB volume mounted on the specified device.
 * Returns 0 on success, or a GS/OS error code.
 * On success, if vcrPtrPtr is non-null, sets *vcrPtrPtr to point to the VCR.
 */
Word GetVCR(DIB *dib, VCR **vcrPtrPtr) {
    bool err;
    Word id;
    VCR *vcr;
    GSString *volName = dib->volName;

    // Find existing VCR, if present.
    asm {
        stz err
        ldx volName
        ldy volName+2
        phd
        lda gsosDP
        tcd
        lda #0
        jsl FIND_VCR
        bcs done1
        jsl DEREF
        clc
done1:  pld
        rol err
        stx vcr
        sty vcr+2
    }
    
    if (!err) {
        if (vcr->fstID == smbFSID
            && vcr->dib == dib
            && vcr->treeConnectID == dib->treeConnectID) {
            if (vcrPtrPtr != NULL)
                *vcrPtrPtr = vcr;
            return 0;
        } else if (vcr->openCount == 0) {
            // Release other VCR with same name, if it has no open files.
            id = vcr->id;
            asm {
                ldx id
                phd
                lda gsosDP
                tcd
                txa
                jsl RELEASE_VCR
                pld
            }
        } else {
            return dupVolume;
        }
    }
    
    // Allocate new VCR
    asm {
        stz err
        ldx volName
        ldy volName+2
        phd
        lda gsosDP
        tcd
        lda #sizeof(VCR)
        jsl ALLOC_VCR
        bcs done2
        jsl DEREF
        clc
done2:  pld
        rol err
        stx vcr
        sty vcr+2
    }
    
    if (err)
        return outOfMem;

    vcr->status = 0;
    vcr->openCount = 0;
    vcr->fstID = smbFSID;
    vcr->devNum = dib->DIBDevNum;
    vcr->dib = dib;
    vcr->treeConnectID = dib->treeConnectID;

    if (vcrPtrPtr != NULL)
        *vcrPtrPtr = vcr;
    return 0;
}
