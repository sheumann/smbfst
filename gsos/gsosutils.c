#include "defs.h"
#include <gsos.h>
#include <string.h>
#include "gsos/gsosutils.h"

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
    VCR *vcr;
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
        if (volNameLen > GBUF_SIZE-2)
            return NULL;

        *(Word *)gbuf = volNameLen;
        memcpy(gbuf+2, path->text+1, volNameLen);
        
        i = 0;
        asm {
            ldx gbuf
            ldy gbuf+2
            phd
            lda gsosdp
            tcd
            lda #0
            jsl FIND_VCR
            bcs no_vcr
            jsl DEREF
            pld
            stx vcr
            sty vcr+2
            bra have_vcr
no_vcr:     pld
            inc i
have_vcr:
        }
        if (i != 0) {
            return NULL;
        }
        
        devNum = vcr->devNum;
    } else {
useDevNum:
        if (num == 1) {
            devNum = gsosdp->dev1Num;
        } else {
            devNum = gsosdp->dev2Num;
        }
    }
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == devNum  && dibs[i].extendedDIBPtr != 0)
            return &dibs[i];
    }
    return NULL;
}
