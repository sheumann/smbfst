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
#include <types.h>
#include "smb2/smb2.h"
#include "smb2/fileinfo.h"
#include "helpers/fsattributes.h"

/*
 * Get filesystem attributes for the FS containing the specified open file.
 * Returns attributes as given by FileFsAttributeInformation (see [MS-FSCC]).
 */
uint32_t GetFSAttributes(DIB *dib, const SMB2_FILEID *fileID) {
    Word result;

    /*
     * Get FS attributes
     */
    queryInfoRequest.InfoType = SMB2_0_INFO_FILESYSTEM;
    queryInfoRequest.FileInfoClass = FileFsAttributeInformation;
    queryInfoRequest.OutputBufferLength =
        sizeof(msg.body) - offsetof(SMB2_QUERY_INFO_Response, Buffer);
    queryInfoRequest.InputBufferOffset = 0;
    queryInfoRequest.Reserved = 0;
    queryInfoRequest.InputBufferLength = 0;
    queryInfoRequest.AdditionalInformation = 0;
    queryInfoRequest.Flags = 0;
    queryInfoRequest.FileId = *fileID;

    result = SendRequestAndGetResponse(dib, SMB2_QUERY_INFO,
        sizeof(queryInfoRequest));
    if (result != rsDone)
        return 0;

    if (queryInfoResponse.OutputBufferLength
        < sizeof(FILE_FS_ATTRIBUTE_INFORMATION))
        return 0;

    if (!VerifyBuffer(
        queryInfoResponse.OutputBufferOffset,
        queryInfoResponse.OutputBufferLength))
        return 0;

#define info ((FILE_FS_ATTRIBUTE_INFORMATION *) \
    ((unsigned char *)&msg.smb2Header + queryInfoResponse.OutputBufferOffset))

    return info->FileSystemAttributes;
}
