#ifndef GUID_H
#define GUID_H

#include <stdint.h>
#include "utils/endian.h"

// GUID/UUID utilities (see RFC 4122)

typedef struct {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_high_and_version;
    uint64_t clock_seq_reserved_and_node; /* including clock_seq_low */
} GUID;

// Initializer for a GUID in Microsoft-style mixed-endian format
#define GUID(a,b,c,d,e) {.time_low = 0x##a, 0x##b, 0x##c, hton64c(0x##d##e)}

#endif
