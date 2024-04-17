#ifndef CREATECONTEXT_H
#define CREATECONTEXT_H

#include <stdbool.h>
#include <stdint.h>

bool AddCreateContext(uint32_t name, const void *data, uint16_t dataLen,
    uint16_t *msgLen);
void *GetCreateContext(uint32_t name, uint16_t *dataLen);

#endif
