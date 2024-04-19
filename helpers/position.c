#include "defs.h"
#include <gsos.h>
#include "smb2/smb2.h"
#include "smb2/fileinfo.h"
#include "helpers/position.h"
#include "helpers/errors.h"

/*
 * Calculate a file position in terms of a base and displacement, as used by
 * SetMark and SetEOF.
 *
 * Returns a GS/OS error code.  If successful, *pos is set to the new position.
 * If eof is non-null, *eof is set to the file's EOF (prior to any changes).
 */
Word CalcPosition(FCR* fcr, DIB* dib, Word base, uint32_t displacement,
    uint64_t *pos, uint64_t *eof) {
    Word result;
    FILE_STANDARD_INFORMATION *info;

    if (eof != NULL || base == eofMinus) {
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
        
        result = SendRequestAndGetResponse(dib->session, SMB2_QUERY_INFO,
            dib->treeId, sizeof(queryInfoRequest));
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

        *pos = info->EndOfFile;

        if (eof)
            *eof = *pos;
    }
    
    switch(base) {
    case startPlus:
        *pos = displacement;
        return 0;
    
    case eofMinus:
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
