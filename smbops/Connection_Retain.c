#include "defs.h"

#include <gsos.h>
#include "connection.h"
#include "fstspecific.h"

Word SMB_Connection_Retain(SMBConnectionRec *pblock, void *gsosdp, Word pcount) {
    if (pblock->pCount != 3)
        return invalidPcount;

    Connection_Retain((Connection *)pblock->connectionID);
    return 0;
}
