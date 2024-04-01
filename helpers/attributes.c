#include "defs.h"
#include <gsos.h>
#include "fileinfo.h"
#include "helpers/attributes.h"

/*
 * Convert SMB FileAttributes ([MS-FSCC] section 2.6) to GS/OS access word.
 */
Word GetAccess(uint32_t attributes) {
    Word access = readEnable | writeEnable | destroyEnable | renameEnable;

    if (attributes & FILE_ATTRIBUTE_ARCHIVE)
        access |= backupNeeded;
    if (attributes & FILE_ATTRIBUTE_HIDDEN)
        access |= fileInvisible;
    if (attributes & FILE_ATTRIBUTE_READONLY) {
        access &= ~destroyEnable;
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY))
            access &= ~writeEnable;
    }
    
    return access;
}
