#ifndef GUID_H
#define GUID_H

#include <stdint.h>

// GUID/UUID (see RFC 9562 and [MS-DTYP])

typedef struct {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_high_and_version;
    uint64_t clock_seq_reserved_and_node; /* including clock_seq_low */
} GUID;

#endif
