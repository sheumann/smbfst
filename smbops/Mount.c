#include "defs.h"
#include <stddef.h>
#include <string.h>
#include <gsos.h>
#include "smb2.h"
#include "fstspecific.h"
#include "driver.h"

#ifndef devListFull
#define devListFull 0x0068
#endif

Word SMB_Mount(SMBMountRec *pblock, void *gsosdp, Word pcount) {
    // TODO use real volume name
    static struct {
        Word len;
        char str[10];
    } volName = {7, "testvol"};

    static ReadStatus result;
    unsigned dibIndex;
    VCR *vcr;

    if (pblock->pCount != 6)
        return invalidPcount;

    for (dibIndex = 0; dibIndex < NDIBS; dibIndex++) {
        if (dibs[dibIndex].extendedDIBPtr == 0)
            break;
    }
    if (dibIndex == NDIBS)
        return devListFull;

    treeConnectRequest.Reserved = 0;
    treeConnectRequest.PathOffset =
        sizeof(SMB2Header) + offsetof(SMB2_TREE_CONNECT_Request, Buffer);
    treeConnectRequest.PathLength = pblock->shareNameSize;
    memcpy(treeConnectRequest.Buffer, pblock->shareName, pblock->shareNameSize);
    
    result = SendRequestAndGetResponse((Session*)pblock->sessionID,
        SMB2_TREE_CONNECT, 0,
        sizeof(treeConnectRequest) + pblock->shareNameSize);
    if (result != rsDone) {
        return networkError;
    }

    dibs[dibIndex].treeId = msg.smb2Header.TreeId;
    dibs[dibIndex].switched = true;
    dibs[dibIndex].extendedDIBPtr = &dibs[dibIndex].treeId;
    
    vcr = NULL;
    asm {
        phd
        lda gsosdp
        tcd
        lda #sizeof(VCR)
        ldx #volName
        ldy #^volName
        jsl ALLOC_VCR
        bcs oom
        jsl DEREF
        pld
        stx vcr
        sty vcr+2
        bra asm_end

oom:    pld
asm_end:
    }
    
    if (!vcr) {
        /*
         * If we're here, VCR allocation failed because we are out of memory.
         * We should probably send a TREE_DISCONNECT message to the server,
         * but we currently don't.  There is a risk that Marinetti may not
         * work right if it cannot allocate memory.
         */
        return outOfMem;
    }

    vcr->status = 0;
    vcr->openCount = 0;
    vcr->fstID = smbFSID;
    vcr->devNum = dibs[dibIndex].DIBDevNum;

    pblock->devNum = dibs[dibIndex].DIBDevNum;
    return 0;
}
