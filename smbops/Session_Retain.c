#include "defs.h"

#include <gsos.h>
#include "smb2/session.h"
#include "fst/fstspecific.h"

Word SMB_Session_Retain(SMBSessionRec *pblock, struct GSOSDP *gsosdp,
    Word pcount) {
    if (pblock->pCount != 3)
        return invalidPcount;

    Session_Retain((Session *)pblock->sessionID);
    return 0;
}
