#include "defs.h"
#include <gsos.h>
#include "smb2.h"
#include "helpers/errors.h"
#include "ntstatus.h"

/*
 * Convert an SMB error code to a GS/OS error.
 *
 * If rs == rsFailed, this converts the error code from msg.smb2Header.Status.
 */
Word ConvertError(ReadStatus rs) {
    if (rs == rsFailed) {
        switch (msg.smb2Header.Status) {
        /*
         * STATUS_OBJECT_NAME_NOT_FOUND could be fileNotFound, pathNotFound,
         * resForkNotFound, or (on macOS) resAddErr.  We can't disambiguate
         * it here, so we just go with the common case of fileNotFound.
         */
        case STATUS_OBJECT_NAME_NOT_FOUND:
        case STATUS_NO_SUCH_FILE:
        case STATUS_NOT_FOUND:
            return fileNotFound;

        case STATUS_ACCESS_DENIED:
        case STATUS_CANNOT_DELETE:
        case STATUS_QUOTA_EXCEEDED:
            return invalidAccess;

        case STATUS_SHARING_VIOLATION:
        case STATUS_FILE_LOCK_CONFLICT:
        case STATUS_DELETE_PENDING:
            return fileBusy;

        case STATUS_END_OF_FILE:
            return eofEncountered;

        case STATUS_OBJECT_NAME_COLLISION:
        case STATUS_FILE_IS_A_DIRECTORY:
            return dupPathname;

        case STATUS_DISK_FULL:
            return volumeFull;

        case STATUS_NOT_SAME_DEVICE:
            return badPathNames;

        case STATUS_NAME_TOO_LONG:
        case STATUS_ILLEGAL_CHARACTER:
        case STATUS_UNMAPPABLE_CHARACTER:
        case STATUS_UNDEFINED_CHARACTER:
            return badPathSyntax;

        case STATUS_TOO_MANY_OPENED_FILES:
            return tooManyFilesOpen;

        case STATUS_NO_MORE_FILES:
            return endOfDir;

        case STATUS_INSUFFICIENT_RESOURCES:
        case STATUS_INSUFF_SERVER_RESOURCES:
        case STATUS_NO_MEMORY:
            return drvrNoResrc;

        case STATUS_SHARING_PAUSED:
            return drvrOffLine;

        case STATUS_VOLUME_DISMOUNTED:
            return drvrDiskSwitch;

        /*
        case STATUS_SERVER_UNAVAILABLE:
        case STATUS_FILE_NOT_AVAILABLE:
        case STATUS_SHARE_UNAVAILABLE:
        case STATUS_DEVICE_DATA_ERROR:
        case STATUS_FILE_CORRUPT_ERROR:
        case STATUS_DISK_CORRUPT_ERROR:
        case STATUS_INVALID_DEVICE_STATE:
        case STATUS_FILE_INVALID:
        case STATUS_FILE_FORCED_CLOSED:
        case STATUS_DEVICE_NOT_CONNECTED:
        case STATUS_DEVICE_NOT_READY:
        case STATUS_UNEXPECTED_IO_ERROR:
        case STATUS_IO_TIMEOUT:
        */
        default:
            return drvrIOError;
        }
    } else if (rs == rsDone) {
        return 0;
    }
    
    return networkError;
}
