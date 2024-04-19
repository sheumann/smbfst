#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include "smb2/smb2.h"
#include "gsos/gsosdata.h"
#include "driver/driver.h"
#include "helpers/errors.h"

/*
 * Flush pblock, including optional flush type as second parameter.
 * (Added in System 5.0.3; see System 5.0.4 release notes.)
 */
typedef struct FlushRecGS {
    Word pCount;
    Word refNum;
    Word flushType;
} FlushRecGS, *FlushRecPtrGS;

// flush type for a fast flush, not necessarily updating access time
#define fastFlush 0x8000

Word Flush(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;
    VirtualPointer vp;
    FCR *fcr;
    unsigned i;

    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num /* TODO && active */)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    if (pcount == 2) {
        /*
         * Validate flush type, if present.
         * Other than this, we don't do anything special for a "fast" flush.
         */
        if ((((FlushRecGS*)pblock)->flushType & ~fastFlush) != 0)
            return paramRangeErr;
    }    

    flushRequest.Reserved1 = 0;
    flushRequest.Reserved2 = 0;
    flushRequest.FileId = fcr->fileID;
    
    result = SendRequestAndGetResponse(dibs[i].session, SMB2_FLUSH,
        dibs[i].treeId, sizeof(flushRequest));
    if (result != rsDone)
        return ConvertError(result);
    
    return 0;
}
