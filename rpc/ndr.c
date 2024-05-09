#define USE_BLANK_SEG
#include "defs.h"
#include <string.h>
#include <stddef.h>
#include "rpc/ndr.h"

/*
 * Network Data Representation handling. See Open Group pub. C706, ch. 14.
 */

void InitNDRBuf(NDRBufInfo *info, void *buf, uint32_t bufSize) {
    info->buf = buf;
    info->pos = buf;
    info->remainingSize = bufSize;
}

void *NDRRead(NDRBufInfo *info, uint32_t size) {
    void *oldPos = info->pos;

    if (info->remainingSize < size)
        return NULL;

    info->pos += size;
    info->remainingSize -= size;
    return oldPos;
}

bool NDRWrite(NDRBufInfo *info, const void *data, uint32_t size) {
    if (info->remainingSize < size)
        return false;
    
    memcpy(info->pos, data, size);
    info->pos += size;
    info->remainingSize -= size;
    return true;
}

bool NDRWritePtr(NDRBufInfo *info, uint32_t val) {
    return NDRWrite(info, &val, 4);
}

bool NDRWriteI32(NDRBufInfo *info, uint32_t val) {
    return NDRWrite(info, &val, 4);
}

uint32_t NDRDataSize(NDRBufInfo *info) {
    return info->pos - info->buf;
}

bool NDRAlign(NDRBufInfo *info, uint16_t alignment) {
    while ((info->pos - info->buf) % alignment != 0) {
        if (info->remainingSize == 0)
            return false;
        
        info->pos++;
    }
    
    return true;
}
