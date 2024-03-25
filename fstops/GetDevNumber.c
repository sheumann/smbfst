#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include "gsosdata.h"
#include "driver.h"
#include "gsosutils.h"

Word GetDevNumber(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word devNum = gsosdp->dev1Num;
    
    if (devNum == 0) {
        DIB *dib = GetDIB(gsosdp, 1);
        if (dib == NULL) {
            // TODO adjust error based on type of path (device or volume name?)
            return devNotFound;
        }
        devNum = dib->DIBDevNum;
    }
    
    if (pcount == 0) {
        #define pblock ((DevNumRec*)pblock)
        
        pblock->devNum = devNum;
        
        #undef pblock
    } else {
        #define pblock ((DevNumRecGS*)pblock)
        
        pblock->devNum = devNum;
        
        #undef pblock
    }

    return 0;
}
