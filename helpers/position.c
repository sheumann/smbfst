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
#include "smb2/smb2.h"
#include "smb2/fileinfo.h"
#include "helpers/position.h"
#include "helpers/errors.h"

/*
 * Get the file's current EOF.
 *
 * Returns a GS/OS error code.  If successful, *eof is set to the EOF.
 */
Word GetEndOfFile(FCR* fcr, DIB* dib, uint64_t *eof) {
    Word result;
    FILE_STANDARD_INFORMATION *info;

    /*
     * Get current EOF
     */
    queryInfoRequest.InfoType = SMB2_0_INFO_FILE;
    queryInfoRequest.FileInfoClass = FileStandardInformation;
    queryInfoRequest.OutputBufferLength = sizeof(FILE_STANDARD_INFORMATION);
    queryInfoRequest.InputBufferOffset = 0;
    queryInfoRequest.Reserved = 0;
    queryInfoRequest.InputBufferLength = 0;
    queryInfoRequest.AdditionalInformation = 0;
    queryInfoRequest.Flags = 0;
    queryInfoRequest.FileId = fcr->fileID;
    
    result = SendRequestAndGetResponse(dib, SMB2_QUERY_INFO,
        sizeof(queryInfoRequest));
    if (result != rsDone)
        return ConvertError(result);
    
    if (queryInfoResponse.OutputBufferLength
        != sizeof(FILE_STANDARD_INFORMATION))
        return networkError;

    if (!VerifyBuffer(
        queryInfoResponse.OutputBufferOffset,
        queryInfoResponse.OutputBufferLength))
        return networkError;

    info = (FILE_STANDARD_INFORMATION *)((unsigned char *)&msg.smb2Header
        + queryInfoResponse.OutputBufferOffset);

    *eof = info->EndOfFile;
    fcr->eof = info->EndOfFile;
    
    return 0;
}

/*
 * Calculate a file position in terms of a base and displacement, as used by
 * SetMark and SetEOF.
 *
 * Returns a GS/OS error code.  If successful, *pos is set to the new position.
 */
Word CalcPosition(FCR* fcr, DIB* dib, Word base, uint32_t displacement,
    uint64_t *pos) {
    Word retval;
    
    switch(base) {
    case startPlus:
        *pos = displacement;
        return 0;
    
    case eofMinus:
        retval = GetEndOfFile(fcr, dib, pos);    
        if (retval != 0)
            return retval;
        if (displacement > *pos)
            return outOfRange;
        *pos -= displacement;
        return 0;

    case markPlus:
        *pos = fcr->mark + displacement;
        if (*pos < fcr->mark)
            return outOfRange;
        return 0;

    case markMinus:
        if (displacement > fcr->mark)
            return outOfRange;
        *pos = fcr->mark - displacement;
        return 0;

    default:
        return paramRangeErr;
    }
}
