#include "defs.h"
#include <gsos.h>
#include "fileinfo.h"
#include "helpers/attributes.h"

// TODO Mac blocks rename if locked. Adjust attributes accordingly.

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

/*
 * Convert GS/OS access word to SMB FileAttributes
 */
uint32_t GetFileAttributes(Word access, bool isDirectory) {
    Word attributes = 0;

    if (access & backupNeeded)
        attributes |= FILE_ATTRIBUTE_ARCHIVE;
    if (access & fileInvisible)
        attributes |= FILE_ATTRIBUTE_HIDDEN;
    if (isDirectory)
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
    /*
     * Note: Per [MS-FSCC], directories with FILE_ATTRIBUTE_READONLY are still
     * writable, so we could set that attribute on directories even if the
     * writeEnable bit (but not destroyEnable) is set.  However, macOS
     * implements FILE_ATTRIBUTE_READONLY as the locked flag, which prohibits
     * writes to directories.  So we only set that bit (on files or directories)
     * if writeEnable and destroyEnable are both clear.
     */
    if ((access & (writeEnable | destroyEnable)) == 0)
        attributes |= FILE_ATTRIBUTE_READONLY;
    
    if (attributes == 0)
        attributes = FILE_ATTRIBUTE_NORMAL;
    
    return attributes;
}
