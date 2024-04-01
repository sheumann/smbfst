#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

#include <stdint.h>
#include <types.h>

/*
 * Convert SMB FileAttributes ([MS-FSCC] section 2.6) to GS/OS access word.
 */
Word GetAccess(uint32_t attributes);

#endif
