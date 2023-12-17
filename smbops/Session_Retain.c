#include "defs.h"

#include <gsos.h>
#include "session.h"
#include "fstspecific.h"

Word SMB_Session_Retain(SMBSessionRec *pblock, void *gsosdp, Word pcount) {
    if (pblock->pCount != 3)
        return invalidPcount;

    Session_Retain((Session *)pblock->sessionID);
    return 0;
}
