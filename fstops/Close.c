#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include "smb2/smb2.h"
#include "gsos/gsosdata.h"
#include "driver/driver.h"

Word Close(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;
    VirtualPointer vp;
    FCR *fcr;
    VCR *vcr;
    unsigned i;
    
    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);

    vp = gsosdp->vcrPtr;
    DerefVP(vcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    closeRequest.Flags = 0;
    closeRequest.Reserved = 0;
    closeRequest.FileId = fcr->fileID;

    result = SendRequestAndGetResponse(&dibs[i], SMB2_CLOSE,
        sizeof(closeRequest));
    if (result != rsDone)
        return networkError;
    
    i = fcr->refNum;
    asm {
        ldx i
        phd
        lda gsosdp
        tcd
        txa
        jsl RELEASE_FCR
        pld
    }

    vcr->openCount--;
    
    return 0;
}
