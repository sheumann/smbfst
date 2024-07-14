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
#include <string.h>
#include <gsos.h>
#include <prodos.h>
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "fst/fstspecific.h"
#include "helpers/blocks.h"
#include "smb2/smb2.h"
#include "smb2/fileinfo.h"
#include "helpers/closerequest.h"
#include "utils/finderstate.h"

Word Volume(void *pblock, struct GSOSDP *gsosDP, Word pcount) {
    unsigned i;
    GSString *volName;
    GSString *pathName;
    Word result;
    uint16_t createMsgNum, queryInfoMsgNum, closeMsgNum;
    SMB2_QUERY_INFO_Request *queryInfoReq;
    FILE_FS_FULL_SIZE_INFORMATION *info;
    static uint64_t totalBlocks, freeBlocks;
    Word retval = 0;

    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    if (pcount != 2) {
        /*
         * Open root directory
         */
        createRequest.SecurityFlags = 0;
        createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
        createRequest.ImpersonationLevel = Impersonation;
        createRequest.SmbCreateFlags = 0;
        createRequest.Reserved = 0;
        createRequest.DesiredAccess = FILE_READ_ATTRIBUTES;
        createRequest.FileAttributes = 0;
        createRequest.ShareAccess =
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        createRequest.CreateDisposition = FILE_OPEN;
        createRequest.CreateOptions = 0;
        createRequest.NameOffset =
            sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
        createRequest.NameLength = 0;
        createRequest.CreateContextsOffset = 0;
        createRequest.CreateContextsLength = 0;
        
        createMsgNum = EnqueueRequest(&dibs[i], SMB2_CREATE,
            sizeof(createRequest));

        /*
         * Get FS size information
         */
        queryInfoReq = (SMB2_QUERY_INFO_Request*)nextMsg->Body;
        // no need to check for space (previous message is fixed-length)
        
        queryInfoReq->InfoType = SMB2_0_INFO_FILESYSTEM;
        queryInfoReq->FileInfoClass = FileFsFullSizeInformation;
        queryInfoReq->OutputBufferLength =
            sizeof(msg.body) - offsetof(SMB2_QUERY_INFO_Response, Buffer);
        queryInfoReq->InputBufferOffset = 0;
        queryInfoReq->Reserved = 0;
        queryInfoReq->InputBufferLength = 0;
        queryInfoReq->AdditionalInformation = 0;
        queryInfoReq->Flags = 0;
        queryInfoReq->FileId = fileIDFromPrevious;
    
        queryInfoMsgNum = EnqueueRequest(&dibs[i], SMB2_QUERY_INFO,
            sizeof(*queryInfoReq));

        /*
         * Close root directory
         */
        closeMsgNum = EnqueueCloseRequest(&dibs[i], &fileIDFromPrevious);
        // Cannot fail, because previous messages are fixed-length

        SendMessages(&dibs[i]);

        result = GetResponse(&dibs[i], createMsgNum);
        if (result != rsDone)
            retval == networkError;
        
        result = GetResponse(&dibs[i], queryInfoMsgNum);
        if (result != rsDone) {
            retval = networkError;
            goto handle_close;
        }
        
        if (queryInfoResponse.OutputBufferLength
            != sizeof(FILE_FS_FULL_SIZE_INFORMATION)) {
            retval = networkError;
            goto handle_close;
        }
    
        if (!VerifyBuffer(
            queryInfoResponse.OutputBufferOffset,
            queryInfoResponse.OutputBufferLength)) {
            retval = networkError;
            goto handle_close;
        }

        info = (FILE_FS_FULL_SIZE_INFORMATION *)((char *)&msg.smb2Header
            + queryInfoResponse.OutputBufferOffset);

        // TODO handle overflows
        totalBlocks = info->TotalAllocationUnits *
            info->SectorsPerAllocationUnit * info->BytesPerSector / BLOCK_SIZE;
        freeBlocks = info->ActualAvailableAllocationUnits *
            info->SectorsPerAllocationUnit * info->BytesPerSector / BLOCK_SIZE;

        // Could have true free blocks > "total" blocks when using quotas
        if (freeBlocks > totalBlocks)
            totalBlocks = freeBlocks;

        totalBlocks = min(totalBlocks, 0xffffffff);
        freeBlocks = min(freeBlocks, 0xffffffff);

        /*
         * If this Volume call is coming from a known version of the Finder,
         * adjust returned values if necessary to work around Finder issues.
         */
        if (CallIsFromFinder(pblock, FINDER_600, FINDER_603)) {
            /*
             * Finder 6.0.1 - 6.0.3 will display garbage in the info
             * bar for unknown FST names.  Setting totalBlocks equal
             * to freeBlocks (so there are no "used" blocks) causes
             * Finder to display the alternate info bar style with
             * just the item count, and therefore prevents it from
             * showing the garbage.  Also, Finder 6.0.1 - 6.0.3 may
             * crash or hang when displaying sizes that are too large
             * (above "99,999.9 MB"), so limit the size to avoid this.
             */
            freeBlocks =
                min(freeBlocks, FINDER_601_MAX_DISPLAYABLE_BLOCKS);
            totalBlocks = freeBlocks;        
        } else if (CallIsFromFinder(pblock, FINDER_604, FINDER_604)) {
            /*
             * Finder 6.0.4 will display the used space or free space
             * incorrectly (in the info bar and the info window) if the
             * values are too large.  In these cases, force the use of
             * the alternate info bar without the incorrect values.
             */
            if (freeBlocks > FINDER_604_MAX_DISPLAYABLE_BLOCKS ||
                totalBlocks-freeBlocks > FINDER_604_MAX_DISPLAYABLE_BLOCKS) {
                totalBlocks = freeBlocks;
            }
        }

handle_close:
        result = GetResponse(&dibs[i], closeMsgNum);
        if (result != rsDone && retval == 0)
            retval = networkError;

        if (retval != 0)
            return retval;
    }

    volName = dibs[i].volName;

    if (volName->length > GBUF_SIZE - 3) {
        // This should not happen in practice
        pathName = NULL;
    } else {
        pathName = (void*)gbuf;
        pathName->length = volName->length + 1;
        pathName->text[0] = (pcount == 0 ? '/' : ':');
        memcpy(pathName->text+1, volName->text, volName->length);
    }

    if (pcount == 0) {
        #define pblock ((VolumeRec*)pblock)
        
        // TODO maybe restrict to shorter length (16 chars, like for ProDOS?)
        if (pathName == NULL ||
            WritePString(pathName->length, pathName->text, pblock->volName))
        {
            retval = buffTooSmall;
        }

        pblock->totalBlocks = totalBlocks;
        pblock->freeBlocks = freeBlocks;
        pblock->fileSysID = smbFSID;
        
        #undef pblock
    } else {
        #define pblock ((VolumeRecGS*)pblock)

        if (pathName == NULL ||
            WriteGSOSString(pathName->length, pathName->text, pblock->volName))
        {
            retval = buffTooSmall;
        }
        
        if (pcount < 3) goto end;
        pblock->totalBlocks = totalBlocks;
        
        if (pcount < 4) goto end;
        pblock->freeBlocks = freeBlocks;

        if (pcount < 5) goto end;
        pblock->fileSysID = smbFSID;
        
        if (pcount < 6) goto end;
        pblock->blockSize = BLOCK_SIZE;
        
        /* Note: GS/OS sets characteristics and deviceID, if necessary */
        
        #undef pblock
    }

end:
    return retval;
}
