#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include "smb2.h"
#include "gsosdata.h"
#include "driver.h"
#include "fileinfo.h"
#include "helpers/errors.h"

Word GetEOF(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;
    VirtualPointer vp;
    FCR *fcr;
    unsigned i;
    uint32_t eof;
    Word retval = 0;
    
    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num /* TODO && active */)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    queryInfoRequest.InfoType = SMB2_0_INFO_FILE;
    queryInfoRequest.FileInfoClass = FileStandardInformation;
    queryInfoRequest.OutputBufferLength = sizeof(FILE_STANDARD_INFORMATION);
    queryInfoRequest.InputBufferOffset = 0;
    queryInfoRequest.Reserved = 0;
    queryInfoRequest.InputBufferLength = 0;
    queryInfoRequest.AdditionalInformation = 0;
    queryInfoRequest.Flags = 0;
    queryInfoRequest.FileId = fcr->fileID;
    
    result = SendRequestAndGetResponse(dibs[i].session, SMB2_QUERY_INFO,
        dibs[i].treeId, sizeof(queryInfoRequest));
    if (result != rsDone)
        return ConvertError(result);
    
    if (queryInfoResponse.OutputBufferLength
        != sizeof(FILE_STANDARD_INFORMATION))
        return networkError;

    if (!VerifyBuffer(
        queryInfoResponse.OutputBufferOffset,
        queryInfoResponse.OutputBufferLength))
        return networkError;

    FILE_STANDARD_INFORMATION *info = (void*)((unsigned char *)&msg.smb2Header
        + queryInfoResponse.OutputBufferOffset);

    if (info->EndOfFile > 0xFFFFFFFF) {
        eof = 0xFFFFFFFF;
        retval = outOfRange;
    } else {
        eof = info->EndOfFile;
    }

    if (pcount == 0) {
        #define pblock ((EOFRec*)pblock)
        pblock->eofPosition = eof;
        #undef pblock
    } else {
        #define pblock ((EOFRecGS*)pblock)
        pblock->eof = eof;
        #undef pblock
    }
    
    return retval;
}
