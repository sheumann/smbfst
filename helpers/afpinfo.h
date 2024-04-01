#ifndef AFPINFO_H
#define AFPINFO_H

#include <stdint.h>
#include <types.h>
#include "driver.h"

/*
 * Finder Info data structure.
 * This has some variation between different OS versions,
 * and between files and directories.
 *
 * For old versions, see Inside Macintosh IV, or Prog. Ref. for System 6.0.
 * For OS X version, see:
 * https://github.com/apple-oss-distributions/SMBClient/blob/rel/SMBClient-431/kernel/netsmb/smb_2.h#L294
 */
typedef struct {
    union {
        struct {                // for files
            uint32_t fileType;
            uint32_t creator;
        };
        uint64_t windRect;      // for directories
    };
    uint16_t finderFlags;
    uint32_t iconLoc;
    union {
        uint16_t fileWindow;    // for files
        uint16_t view;          // for directories
    };
    union {
        struct {                // for files
            uint16_t iconID;
            uint16_t reserved1;
        };
        uint32_t position;      // for directories
    };
    union {
        uint32_t dateAdded;     // in OS X
        uint32_t nextID;        // for directories, pre-OS X
        uint32_t reserved2;     // for files, pre-OS X
    };
    union {
        uint16_t extFlags;      // in OS X
        uint16_t reserved3;     // pre-OS X
    };
    uint16_t commentID;
    uint32_t directoryID;
} FinderInfo;

#define AFPINFO_SIGNATURE 0x00504641 /* "AFP\0" */
#define AFPINFO_VERSION   0x00010000

/*
 * AFP_AfpInfo data stream structure.
 * See:
 * https://gitlab.com/samba-team/samba/-/blob/samba-4.20.0/source3/include/MacExtensions.h#L46
 * https://groups.google.com/g/microsoft.public.win2000.macintosh/c/ckHnOh6iDEM/m/8uxvGbKkolMJ
 */
typedef struct {
    uint32_t signature;
    uint32_t version;
    uint32_t reserved1;
    uint32_t backupTime;
    FinderInfo finderInfo;
    uint16_t prodosType;
    uint32_t prodosAuxType;
    uint8_t  reserved2[6];
    /* Samba may include an extra field beyond this */
} AFPInfo;

extern AFPInfo afpInfo;

Word GetFinderInfo(DIB *dib, struct GSOSDP *gsosdp);

#endif
