#include "defs.h"
#include <stdlib.h>
#include <gsos.h>
#include <orca.h>
#include "cdev/loginsmb.h"
#include "cdev/charset.h"
#include "cdev/errorcodes.h"
#include "fst/fstspecific.h"

SMBAuthenticateRec authenticatePB = {
    .pCount = 11,
    .fileSysID = smbFSID,
    .commandNum = SMB_AUTHENTICATE,
    .flags = 0,
};

unsigned LoginToSMBServer(char *username, char *password, char *domain,
    LongWord connectionID, LongWord *sessionID) {
    unsigned result = 0;

    UTF16String *user = NULL;
    UTF16String *pass = NULL;
    UTF16String *dom = NULL;

    user = MacRomanToUTF16(username);
    pass = MacRomanToUTF16(password);
    dom = MacRomanToUTF16(domain);
    
    if (user == NULL || pass == NULL || dom == NULL) {
        result = oomError;
        goto cleanup;
    }

    authenticatePB.connectionID = connectionID;
    authenticatePB.userName = user->text;
    authenticatePB.userNameSize = user->length;
    authenticatePB.password = pass->text;
    authenticatePB.passwordSize = pass->length;
    authenticatePB.userDomain = dom->text;
    authenticatePB.userDomainSize = dom->length;

    FSTSpecific(&authenticatePB);
    if (toolerror()) {
        result = authenticateError;
        goto cleanup;
    }

    *sessionID = authenticatePB.sessionID;

cleanup:
    free(user);
    free(pass);
    free(dom);
    return result;
}
