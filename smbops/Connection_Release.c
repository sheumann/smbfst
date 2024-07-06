#include "defs.h"

#include <gsos.h>
#include "smb2/connection.h"
#include "fst/fstspecific.h"

Word SMB_Connection_Release(SMBConnectionRec *pblock, struct GSOSDP *gsosdp,
    Word pcount) {
    if (pblock->pCount != 3)
        return invalidPcount;

    Connection_Release((Connection *)pblock->connectionID);
    return 0;
}
