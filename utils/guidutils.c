#include "defs.h"
#include <string.h>
#include "utils/guidutils.h"
#include "utils/random.h"

#define VERSION_MASK 0xf000     /* within time_high_and_version */
#define VERSION(n) ((n) << 12)  /* version encoding in time_high_and_version */

#define VARIANT_MASK 0x00000000000000c0ULL /* in clock_seq_reserved_and_node */
#define VARIANT_1    0x0000000000000080ULL

/*
 * Generate a new GUID.
 */
void GenerateGUID(GUID *guid) {
    memcpy(guid, GetRandom(), sizeof(GUID));

    guid->time_high_and_version &= ~VERSION_MASK;
    guid->time_high_and_version |= VERSION(4);
    
    guid->clock_seq_reserved_and_node &= ~VARIANT_MASK;
    guid->clock_seq_reserved_and_node |= VARIANT_1;
}
