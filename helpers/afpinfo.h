/*
 * Copyright (c) 2024 Stephen Heumann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef AFPINFO_H
#define AFPINFO_H

#include <stdint.h>
#include <stdbool.h>
#include <uchar.h>
#include <types.h>
#include "driver/driver.h"

/*
 * Mac-style type/creator code
 */
typedef struct {
    uint32_t type;
    uint32_t creator;
} TypeCreator;

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
        TypeCreator typeCreator; // for files
        uint64_t windRect;       // for directories
    };
    uint16_t finderFlags;
    uint32_t iconLoc;
    union {
        uint16_t fileWindow;     // for files
        uint16_t view;           // for directories
    };
    union {
        struct {                 // for files
            uint16_t iconID;
            uint16_t reserved1;
        };
        uint32_t position;       // for directories
    };
    union {
        uint32_t dateAdded;      // in OS X
        uint32_t nextID;         // for directories, pre-OS X
        uint32_t reserved2;      // for files, pre-OS X
    };
    union {
        uint16_t extFlags;       // in OS X
        uint16_t reserved3;      // pre-OS X
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

extern const char16_t afpInfoSuffix[18];
extern const char16_t resourceForkSuffix[19];

extern AFPInfo afpInfo;

Word GetAFPInfo(DIB *dib, struct GSOSDP *gsosdp);
bool AFPInfoValid(AFPInfo *info);
void InitAFPInfo(void);

#endif
