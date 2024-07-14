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
#include <gsos.h>
#include <prodos.h>
#include <string.h>
#include "smb2/smb2.h"
#include "gsos/gsosdata.h"
#include "driver/driver.h"
#include "helpers/errors.h"
#include "fst/fstdata.h"

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
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
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
        if (dibs[i].flags & FLAG_PIPE_SHARE) {
            writeRequest.Offset = 0;
        } else {
            writeRequest.Offset = fcr->mark;
        }
        writeRequest.FileId = fcr->fileID;
        writeRequest.Channel = 0;
        writeRequest.RemainingBytes = 0;
        writeRequest.WriteChannelInfoOffset = 0;
        writeRequest.WriteChannelInfoLength = 0;
        writeRequest.Flags = 0;
        memcpy(writeRequest.Buffer, buf, writeRequest.Length);

        result = SendRequestAndGetResponse(&dibs[i], SMB2_WRITE,
            sizeof(writeRequest) + transferCount);
        if (result != rsDone)
            break;

        volChangedDevNum = dibs[i].DIBDevNum;

        if (writeResponse.Count == 0 || writeResponse.Count > transferCount)
            return networkError;
        
        remainingCount -= writeResponse.Count;
        buf += writeResponse.Count;
        pblock->transferCount += writeResponse.Count;
        fcr->mark += writeResponse.Count;
    } while (remainingCount != 0);
    
    if (fcr->mark > fcr->eof)
        fcr->eof = fcr->mark;
    
    if (remainingCount == 0) {
        return 0;
    } else {
        return ConvertError(result);
    }
}
