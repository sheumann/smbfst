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
#include <uchar.h>
#include <stddef.h>
#include <string.h>
#include "smb2/smb2.h"
#include "smb2/fileinfo.h"
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "helpers/path.h"
#include "helpers/errors.h"
#include "helpers/closerequest.h"
#include "fst/fstdata.h"

Word ClearBackupBit(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    ReadStatus result;
    DIB *dib;
    SMB2_FILEID fileID;
    uint32_t attributes;
    Word retval = 0;

    dib = GetDIB(gsosdp, 1);
    if (dib == NULL)
        return volNotFound;
    
    /*
     * Open file for writing attributes
     */
    createRequest.SecurityFlags = 0;
    createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    createRequest.ImpersonationLevel = Impersonation;
    createRequest.SmbCreateFlags = 0;
    createRequest.Reserved = 0;
    createRequest.DesiredAccess = FILE_WRITE_ATTRIBUTES;
    createRequest.FileAttributes = 0;
    createRequest.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
    createRequest.CreateDisposition = FILE_OPEN;
    createRequest.CreateOptions = 0;
    createRequest.NameOffset =
        sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
    createRequest.CreateContextsOffset = 0;
    createRequest.CreateContextsLength = 0;

    // translate filename to SMB format
    createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1, createRequest.Buffer,
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
    if (createRequest.NameLength == 0xFFFF)
        return badPathSyntax;

    result = SendRequestAndGetResponse(dib, SMB2_CREATE,
        sizeof(createRequest) + createRequest.NameLength);
    if (result != rsDone)
        return ConvertError(result);
    
    fileID = createResponse.FileId;
    attributes = createResponse.FileAttributes;
    
    /*
     * Clear archive bit
     */
    setInfoRequest.InfoType = SMB2_0_INFO_FILE;
    setInfoRequest.FileInfoClass = FileBasicInformation;
    setInfoRequest.BufferLength = sizeof(FILE_BASIC_INFORMATION);
    setInfoRequest.BufferOffset =
        sizeof(SMB2Header) + offsetof(SMB2_SET_INFO_Request, Buffer);
    setInfoRequest.Reserved = 0;
    setInfoRequest.AdditionalInformation = 0;
    setInfoRequest.FileId = fileID;
#define info ((FILE_BASIC_INFORMATION *)setInfoRequest.Buffer)
    info->CreationTime = 0;
    info->LastAccessTime = 0;
    info->LastWriteTime = 0;
    info->ChangeTime = 0;
    info->FileAttributes = attributes & ~(uint32_t)FILE_ATTRIBUTE_ARCHIVE;
    if (info->FileAttributes == 0)
        info->FileAttributes = FILE_ATTRIBUTE_NORMAL;
    info->Reserved = 0;
#undef info

    result = SendRequestAndGetResponse(dib, SMB2_SET_INFO,
        sizeof(setInfoRequest) + sizeof(FILE_BASIC_INFORMATION));
    if (result != rsDone)
        retval = ConvertError(result);

    if (!retval)
        volChangedDevNum = dib->DIBDevNum;

    /*
     * Close file
     */
    result = SendCloseRequestAndGetResponse(dib, &fileID);
    if (result != rsDone)
        return retval ? retval : ConvertError(result);

    return retval;
}
