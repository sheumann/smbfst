#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#undef JudgeName
#include "gsos/gsosdata.h"
#include "fst/fstspecific.h"
#include "helpers/path.h"

// JudgeName name types
#define NAME_TYPE_UNKNOWN        0
#define NAME_TYPE_VOLUME_NAME    1
#define NAME_TYPE_DIRECTORY_NAME 2
#define NAME_TYPE_FILE_NAME      3

// JudgeName flag bits
#define FLAG_NAME_CONTAINED_ILLEGAL_CHARACTERS 0x8000
#define FLAG_NAME_TOO_LONG                     0x4000
#define FLAG_SYNTAX_ERROR                      0x2000

Word JudgeName(JudgeNameRecGS *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word flags;
    Word i;
    ResultBuf *name;

    if (pblock->fileSysID != smbFSID)
        return invalidFSTID;

    if (pblock->nameType > NAME_TYPE_FILE_NAME)
        return paramRangeErr;
    
    pblock->syntax =
        "\pSMB names may contain up to 255 Unicode characters. "
        "Some servers may disallow certain names.";

    if (pcount >= 4) {
        pblock->maxLen = SMB2_MAX_NAME_LEN;

    if (pcount >= 5) {
        flags = 0;

        name = pblock->name;
        if (name != NULL) {
            /*
             * Other FSTs require a big enough buffer to fit a max-length name.
             * We intentionally do not, since 
             * (a) we do not expand the size of names (except "" to "A"), and
             * (b) existing programs may use smaller buffers.
             */
            if (name->bufSize < 5)
                return buffTooSmall;
       
            if (name->bufString.length == 0) {
                name->bufString.length = 1;
                name->bufString.text[0] = 'A';
                flags = FLAG_SYNTAX_ERROR;
            } else {
                for (i = 0; i < name->bufString.length; i++) {
                    if (name->bufString.text[i] == 0
                        || name->bufString.text[i] == ':') {
                        name->bufString.text[i] = '_';
                        flags |= FLAG_NAME_CONTAINED_ILLEGAL_CHARACTERS;
                    }
                }

                if (name->bufString.length > SMB2_MAX_NAME_LEN) {
                    if (GSPathToSMB(&name->bufString, gbuf, GBUF_SIZE)
                        > SMB2_MAX_NAME_LEN * sizeof(char16_t)) {
                        flags |= FLAG_NAME_TOO_LONG;
                        name->bufString.length = SMB2_MAX_NAME_LEN;
                    }
                }
            }
        }
    
    if (pcount >= 6) {
        pblock->nameFlags = flags;
    }}}

    return 0;
}
