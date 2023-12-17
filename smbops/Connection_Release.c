#include "defs.h"

#include <gsos.h>
#include "connection.h"
#include "fstspecific.h"

Word SMB_Connection_Release(SMBConnectionRec *pblock, void *gsosdp, Word pcount) {
    if (pblock->pCount != 3)
        return invalidPcount;

    Connection_Release((Connection *)pblock->connectionID);
    return 0;
}
