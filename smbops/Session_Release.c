#include "defs.h"

#include <gsos.h>
#include "smb2/session.h"
#include "fst/fstspecific.h"

Word SMB_Session_Release(SMBSessionRec *pblock, void *gsosdp, Word pcount) {
    if (pblock->pCount != 3)
        return invalidPcount;

    Session_Release((Session *)pblock->sessionID);
    return 0;
}
