#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <stddef.h>
#include "smb2/smb2.h"
#include "smb2/fileinfo.h"
#include "gsos/gsosdata.h"
#include "driver/driver.h"
#include "helpers/position.h"
#include "helpers/errors.h"

Word SetEOF(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;
    VirtualPointer vp;
    FCR *fcr;
    unsigned i;
    Word retval = 0;

    uint64_t eof;
    Word base;
    uint32_t displacement;

    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    if (pcount == 0) {
        #define pblock ((EOFRec*)pblock)

        base = startPlus;
        displacement = pblock->eofPosition;

        #undef pblock
    } else {
        #define pblock ((SetPositionRecGS*)pblock)
        
        base = pblock->base;
        displacement = pblock->displacement;
        
        #undef pblock
    }
    
    retval = CalcPosition(fcr, &dibs[i], base, displacement, &eof);
    if (retval != 0)
        return retval;

    /*
     * Set EOF
     */
    setInfoRequest.InfoType = SMB2_0_INFO_FILE;
    setInfoRequest.FileInfoClass = FileEndOfFileInformation;
    setInfoRequest.BufferOffset =
        sizeof(SMB2Header) + offsetof(SMB2_SET_INFO_Request, Buffer);
    setInfoRequest.BufferLength = sizeof(FILE_END_OF_FILE_INFORMATION);
    setInfoRequest.Reserved = 0;
    setInfoRequest.AdditionalInformation = 0;
    setInfoRequest.FileId = fcr->fileID;
#define info ((FILE_END_OF_FILE_INFORMATION *)setInfoRequest.Buffer)
    info->EndOfFile = eof;

    result = SendRequestAndGetResponse(&dibs[i], SMB2_SET_INFO,
        sizeof(setInfoRequest) + setInfoRequest.BufferLength);
    if (result != rsDone)
        return ConvertError(result);

    fcr->eof = eof;

    return retval;
}
