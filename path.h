#ifndef PATH_H
#define PATH_H

#include <stdint.h>
#include "gsosdata.h"

unsigned GSOSDPPathToSMB(
    struct GSOSDP *gsosdp, int num, uint8_t *smbpath, unsigned bufsize);
unsigned GSPathToSMB(GSString *gspath, uint8_t *smbpath, unsigned bufsize);
Word SMBNameToGS(char16_t *name, uint16_t length, ResultBuf* buf);

#endif
