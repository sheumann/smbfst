#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <uchar.h>
#include <stddef.h>
#include <string.h>
#include "smb2.h"
#include "driver.h"
#include "gsosutils.h"

Word ClearBackupBit(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    ReadStatus result;
    DIB *dib;

    dib = GetDIB(gsosdp, 1);
    if (dib == NULL)
        return volNotFound;
    
    return 0;
}
