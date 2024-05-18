#include "defs.h"
#include <gsos.h>
#include "smb2/fileinfo.h"
#include "helpers/attributes.h"
#include "driver/driver.h"

/*
 * These functions map between SMB FileAttributes ([MS-FSCC] section 2.6)
 * and a GS/OS-style access word.
 *
 * Note: macOS maps FILE_ATTRIBUTE_READONLY to the "Locked" flag (uchg),
 * which has different semantics from those specified in [MS-FSCC] for
 * FILE_ATTRIBUTE_READONLY.  Specifically, the uchg flag prevents the file
 * from being modified, deleted, or renamed.  It is also fully effective
 * on directories, blocking any addition/deletion/renaming of files in the
 * the directory, as well as deletion or renaming of the directory itself.
 * Because of this, we try to detect if the server is a Mac, and map the
 * meaning of FILE_ATTRIBUTE_READONLY accordingly.
 */

/*
 * Convert SMB FileAttributes ([MS-FSCC] section 2.6) to GS/OS access word.
 */
Word GetAccess(uint32_t attributes, DIB *dib) {
    Word access = readEnable | writeEnable | destroyEnable | renameEnable;

    if (attributes & FILE_ATTRIBUTE_ARCHIVE)
        access |= backupNeeded;
    if (attributes & FILE_ATTRIBUTE_HIDDEN)
        access |= fileInvisible;
    if (attributes & FILE_ATTRIBUTE_READONLY) {
        access &= ~destroyEnable;
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY))
            access &= ~writeEnable;
        if (dib->flags & FLAG_MACOS)
            access &= ~(writeEnable | renameEnable);
    }
    
    return access;
}

/*
 * Convert GS/OS access word to SMB FileAttributes.
 */
uint32_t GetFileAttributes(Word access, bool isDirectory, DIB *dib) {
    Word attributes = 0;

    if (access & backupNeeded)
        attributes |= FILE_ATTRIBUTE_ARCHIVE;
    if (access & fileInvisible)
        attributes |= FILE_ATTRIBUTE_HIDDEN;
    if (isDirectory)
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
    if (dib->flags & FLAG_MACOS) {
        if ((access & (writeEnable | destroyEnable | renameEnable)) == 0)
            attributes |= FILE_ATTRIBUTE_READONLY;
    } else if (isDirectory) {
        if ((access & destroyEnable) == 0)
            attributes |= FILE_ATTRIBUTE_READONLY;    
    } else {
        if ((access & (writeEnable | destroyEnable)) == 0)
            attributes |= FILE_ATTRIBUTE_READONLY;
    }
    
    if (attributes == 0)
        attributes = FILE_ATTRIBUTE_NORMAL;
    
    return attributes;
}
