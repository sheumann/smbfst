#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <string.h>
#include "smb2.h"
#include "gsosdata.h"
#include "driver.h"
#include "helpers/errors.h"

Word Write(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;
    VirtualPointer vp;
    FCR *fcr;
    unsigned i;
    unsigned char *buf;
    uint32_t remainingCount;
    uint16_t transferCount;

    if (pcount != 0)
        pblock = &(((IORecGS*)pblock)->refNum);
    #define pblock ((FileIORec*)pblock)
    
    pblock->transferCount = 0;

    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num /* TODO && active */)
            break;
    }
    if (i == NDIBS)
        return volNotFound;
    
    buf = (void*)pblock->dataBuffer;
    remainingCount = pblock->requestCount;
    
    // TODO should we send a zero-length write request in this case?
    if (remainingCount == 0)
        return 0;
    
    do {
        transferCount = min(remainingCount, IO_BUFFER_SIZE);
        writeRequest.DataOffset =
            sizeof(SMB2Header) + offsetof(SMB2_WRITE_Request, Buffer);
        writeRequest.Length = transferCount;
        writeRequest.Offset = fcr->mark;
        writeRequest.FileId = fcr->fileID;
        writeRequest.Channel = 0;
        writeRequest.RemainingBytes = 0;
        writeRequest.WriteChannelInfoOffset = 0;
        writeRequest.WriteChannelInfoLength = 0;
        writeRequest.Flags = 0;
        memcpy(writeRequest.Buffer, buf, writeRequest.Length);

        result = SendRequestAndGetResponse(dibs[i].session, SMB2_WRITE,
            dibs[i].treeId, sizeof(writeRequest) + transferCount);
        if (result != rsDone)
            break;
        
        if (writeResponse.Count == 0 || writeResponse.Count > transferCount)
            return networkError;
        
        remainingCount -= writeResponse.Count;
        buf += writeResponse.Count;
        pblock->transferCount += writeResponse.Count;
        fcr->mark += writeResponse.Count;
    } while (remainingCount != 0);
    
    if (remainingCount == 0) {
        return 0;
    } else {
        return ConvertError(result);
    }
}
