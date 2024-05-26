#ifndef GUIDUTILS_H
#define GUIDUTILS_H

#include "smb2/guid.h"
#include "utils/endian.h"

// Initializer for a GUID in Microsoft-style mixed-endian format
#define GUID(a,b,c,d,e) {.time_low = 0x##a, 0x##b, 0x##c, hton64c(0x##d##e)}

void GenerateGUID(GUID *guid);

#endif
