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
#include <string.h>
#include <stdbool.h>
#include <gsos.h>
#include "smb2/smb2.h"
#include "smb2/aapl.h"
#include "smb2/treeconnect.h"
#include "fst/fstspecific.h"
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "utils/alloc.h"

static uint32_t treeConnectCounter = 0;

Word SMB_Mount(SMBMountRec *pblock, struct GSOSDP *gsosdp, Word pcount) {
    unsigned dibIndex;
    Session *session = (Session*)pblock->sessionID;
    Word errCode;

    if (pblock->pCount != 7)
        return invalidPcount;

    for (dibIndex = 0; dibIndex < NDIBS; dibIndex++) {
        if (dibs[dibIndex].extendedDIBPtr == 0)
            break;
    }
    if (dibIndex == NDIBS)
        return devListFull;

    dibs[dibIndex].shareName = smb_malloc(pblock->shareNameSize);
    if (dibs[dibIndex].shareName == NULL)
        return outOfMem;
    memcpy(dibs[dibIndex].shareName, pblock->shareName, pblock->shareNameSize);

    dibs[dibIndex].volName = smb_malloc(pblock->volName->length + 2UL);
    if (dibs[dibIndex].volName == NULL) {
        smb_free(dibs[dibIndex].shareName);
        return outOfMem;
    }
    memcpy(dibs[dibIndex].volName, pblock->volName,
        pblock->volName->length + 2UL);

    dibs[dibIndex].shareNameSize = pblock->shareNameSize;
    dibs[dibIndex].session = session;
    dibs[dibIndex].treeId = 0;
    
    errCode = TreeConnect(&dibs[dibIndex]);
    if (errCode) {
        smb_free(dibs[dibIndex].shareName);
        smb_free(dibs[dibIndex].volName);
        return errCode;
    }
    
    dibs[dibIndex].treeConnectID = ++treeConnectCounter;

    errCode = GetVCR(&dibs[dibIndex], NULL);
    if (errCode) {
        /*
         * If we're here, VCR allocation failed, maybe due to lack of memory.
         * We should probably send a TREE_DISCONNECT message to the server,
         * but we currently don't.  There is a risk that Marinetti may not
         * work right if it cannot allocate memory.
         */
        smb_free(dibs[dibIndex].shareName);
        smb_free(dibs[dibIndex].volName);
        return errCode;
    }

    dibs[dibIndex].switched = true;
    dibs[dibIndex].extendedDIBPtr = &dibs[dibIndex].treeId;

    pblock->devNum = dibs[dibIndex].DIBDevNum;
    
    Session_Retain(session);
    return 0;
}
