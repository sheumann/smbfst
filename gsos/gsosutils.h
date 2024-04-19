#ifndef GSOSUTILS_H
#define GSOSUTILS_H

#include <gsos.h>
#include "gsos/gsosdata.h"
#include "driver/driver.h"

Word WriteGSOSString(Word length, char *str, ResultBufPtr buf);
Word WritePString(Word length, char *str, char *buf);
DIB *GetDIB(struct GSOSDP *gsosdp, int num);

#endif