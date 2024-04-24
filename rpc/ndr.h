#ifndef NDR_H
#define NDR_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    unsigned char *buf;
    unsigned char *pos;
    uint32_t       remainingSize;
} NDRBufInfo;

/*
 * This typedef applies to NULL pointers, pointers with deferred referents,
 * or pointers referring to a previously-specified referent.  Pointers not
 * in these categories will have the actual data after the 4-byte identifier.
 */
typedef uint32_t ndr_ptr;

#define NDR_PTR(t) ndr_ptr

#define NDR_UNION(t) struct {               \
    uint32_t tag;   /* type could differ */ \
    t data;                                 \
}

#define NDR_CONFORMANT_ARRAY(t) struct {    \
    uint32_t maxCount;                      \
    t data[];                               \
}

#define NDR_CONFORMANT_VARYING_STRING(t) struct {   \
    uint32_t maxCount;                              \
    uint32_t offset;                                \
    uint32_t actualCount;                           \
    t data[];                                       \
}

// NDR pointer values
#define NDR_NULL      0
#define NDR_ARBITRARY 1

void InitNDRBuf(NDRBufInfo *info, void *buf, uint32_t bufSize);
void *NDRRead(NDRBufInfo *info, uint32_t size);
bool NDRWrite(NDRBufInfo *info, const void *data, uint32_t size);
bool NDRWritePtr(NDRBufInfo *info, uint32_t val);
bool NDRWriteI32(NDRBufInfo *info, uint32_t val);
uint32_t NDRDataSize(NDRBufInfo *info);
bool NDRAlign(NDRBufInfo *info, uint16_t alignment);

#endif
