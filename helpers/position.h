#ifndef POSITION_H
#define POSITION_H

#include <stdint.h>
#include <types.h>
#include "gsos/gsosdata.h"
#include "driver/driver.h"

Word CalcPosition(FCR* fcr, DIB* dib, Word base, uint32_t displacement,
    uint64_t *pos, uint64_t *eof);

#endif
