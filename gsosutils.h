#include <gsos.h>
#include "fstdata.h"
#include "driver.h"

Word WriteGSOSString(Word length, char *str, ResultBufPtr buf);
Word WritePString(Word length, char *str, char *buf);
DIB *GetDIB(struct GSOSDP *gsosdp, int num);
