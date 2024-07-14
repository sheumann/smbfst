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

#include "defs.h"
#include <stddef.h>
#include <finder.h>
#include <locator.h>
#include <memory.h>
#include <orca.h>
#include "utils/finderstate.h"

// Information for currently-running Finder (both 0 if Finder is not running)
Word finderUserID;
LongWord finderVersion;

/*
 * Request procedure which may be called by the Finder.
 */
#pragma databank 1
#pragma toolparms 1
static pascal Word FinderRequestProc(Word reqCode, Long dataIn, void *dataOut) {
    if (reqCode == finderSaysHello) {
        finderUserID = ((finderSaysHelloIn *)dataIn)->finderUserID;
        finderVersion = ((finderSaysHelloIn *)dataIn)->versNum;
        return 0x8000;
    } else if (reqCode == finderSaysGoodbye) {
        finderUserID = 0;
        finderVersion = 0;
        return 0x8000;
    } else {
        return 0;
    }    
}
#pragma toolparms 0
#pragma databank 0

/*
 * Install the request procedure to handle finderSays... requests.
 */
void InstallFinderRequestProc(void) {
    AcceptRequests(
        "\pSTH~SMBFST~", userid() & 0xf0ff, (WordProcPtr)&FinderRequestProc);
}

/*
 * Check if a call is coming from the Finder, with Finder version within the
 * specified (inclusive) range.
 */
bool CallIsFromFinder(void *pblock, LongWord minVersion, LongWord maxVersion) {
    Handle pblockHandle;

    if (finderVersion < minVersion || finderVersion > maxVersion)
        return false;

    pblockHandle = FindHandle(pblock);
    if (pblockHandle == NULL)
        return false;

    return SetHandleID(0, pblockHandle) == finderUserID;
}
