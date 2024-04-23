#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <string.h>
#include "smb2/smb2.h"
#include "gsos/gsosdata.h"
#include "driver/driver.h"
#include "helpers/errors.h"

Word Read(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;
    VirtualPointer vp;
    FCR *fcr;
    unsigned i, j, ch;
    unsigned char *buf;
    uint32_t remainingCount;
    uint16_t transferCount;
    unsigned char *newlineList;
    Word retval;

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
    
    if (remainingCount == 0)
        return 0;
    
    do {
        transferCount = min(remainingCount, IO_BUFFER_SIZE);
        readRequest.Padding =
            sizeof(SMB2Header) + offsetof(SMB2_READ_Response, Buffer);
        readRequest.Flags = 0;
        readRequest.Length = transferCount;
        if (dibs[i].flags & FLAG_PIPE_SHARE) {
            readRequest.Offset = 0;
        } else {
            readRequest.Offset = fcr->mark;
        }
        readRequest.FileId = fcr->fileID;
        readRequest.MinimumCount = 1;
        readRequest.Channel = 0;
        readRequest.RemainingBytes = 0;
        readRequest.ReadChannelInfoOffset = 0;
        readRequest.ReadChannelInfoLength = 0;

        result = SendRequestAndGetResponse(dibs[i].session, SMB2_READ,
            dibs[i].treeId, sizeof(readRequest));
        if (result != rsDone)
            break;
        
        if (readResponse.DataLength == 0
            || readResponse.DataLength > transferCount)
            return networkError;

        if (!VerifyBuffer(readResponse.DataOffset, readResponse.DataLength))
            return networkError;

        // newline processing
        if (fcr->newlineLen != 0) {
            vp = fcr->newline;
            DerefVP(newlineList, vp);
            for (i = 0; i < readResponse.DataLength; i++) {
                ch = ((uint8_t *)&msg.smb2Header)[readResponse.DataOffset + i]
                    & fcr->mask;
                for (j = 0; j < fcr->newlineLen; j++) {
                    if (ch == newlineList[j]) {
                        readResponse.DataLength = remainingCount = i + 1;
                        goto newline_done;
                    }
                }
            }
        }
newline_done:

        memcpy(buf, (unsigned char *)&msg.smb2Header + readResponse.DataOffset,
            readResponse.DataLength);
        
        remainingCount -= readResponse.DataLength;
        buf += readResponse.DataLength;
        pblock->transferCount += readResponse.DataLength;
        fcr->mark += readResponse.DataLength;
    } while (remainingCount != 0);
    
    if (remainingCount == 0) {
        return 0;
    } else {
        retval = ConvertError(result);
        
        if (retval == eofEncountered && pblock->transferCount !=  0)
            retval = 0;
        
        return retval;
    }
}
