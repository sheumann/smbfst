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
#include "smb2/smb2.h"
#include "helpers/path.h"
#include "helpers/afpinfo.h"
#include "helpers/errors.h"
#include "helpers/closerequest.h"

AFPInfo afpInfo;

const char16_t afpInfoSuffix[18] = u":AFP_AfpInfo:$DATA";
const char16_t resourceForkSuffix[19] = u":AFP_Resource:$DATA";

/*
 * Get the AFP Info data stream for a file.
 * This fills in afpInfo with the info.  Returns a GS/OS result code.
 */
Word GetAFPInfo(DIB *dib, struct GSOSDP *gsosdp) {
    ReadStatus result;
    Word retval = 0;
    SMB2_READ_Request *readReq;
    uint16_t createMsgNum, readMsgNum, closeMsgNum;
    
    memset(&afpInfo, 0, sizeof(AFPInfo));

    /*
     * Open AFP Info ADS
     */
    createRequest.SecurityFlags = 0;
    createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
    createRequest.ImpersonationLevel = Impersonation;
    createRequest.SmbCreateFlags = 0;
    createRequest.Reserved = 0;
    createRequest.DesiredAccess = FILE_READ_DATA;
    createRequest.FileAttributes = 0;
    createRequest.ShareAccess = FILE_SHARE_READ;
    createRequest.CreateDisposition = FILE_OPEN;
    createRequest.CreateOptions = 0; // TODO maybe FILE_NO_EA_KNOWLEDGE
    createRequest.NameOffset =
        sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
    createRequest.CreateContextsOffset = 0;
    createRequest.CreateContextsLength = 0;

    // translate filename to SMB format
    createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1, createRequest.Buffer,
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
    if (createRequest.NameLength == 0xFFFF)
        return badPathSyntax;

    if (createRequest.NameLength >
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer)
        - sizeof(afpInfoSuffix))
        return badPathSyntax;

    memcpy(createRequest.Buffer + createRequest.NameLength,
        afpInfoSuffix, sizeof(afpInfoSuffix));
    createRequest.NameLength += sizeof(afpInfoSuffix);
    
    createMsgNum = EnqueueRequest(dib, SMB2_CREATE,
        sizeof(createRequest) + createRequest.NameLength);

    /*
     * Read AFP Info
     */
    readReq = (SMB2_READ_Request*)nextMsg->Body;
    if (!SpaceAvailable(sizeof(*readReq)))
        return fstError;
    
    readReq->Padding =
        sizeof(SMB2Header) + offsetof(SMB2_READ_Response, Buffer);
    readReq->Flags = 0;
    readReq->Length = sizeof(AFPInfo);
    readReq->Offset = 0;
    readReq->FileId = fileIDFromPrevious;
    readReq->MinimumCount = sizeof(AFPInfo);
    readReq->Channel = 0;
    readReq->RemainingBytes = 0;
    readReq->ReadChannelInfoOffset = 0;
    readReq->ReadChannelInfoLength = 0;

    readMsgNum = EnqueueRequest(dib, SMB2_READ, sizeof(*readReq));

    /*
     * Close AFP Info ADS
     */
    closeMsgNum = EnqueueCloseRequest(dib, &fileIDFromPrevious);
    if (closeMsgNum == 0xFFFF)
        return fstError;

    SendMessages(dib);

    result = GetResponse(dib, createMsgNum);
    if (result != rsDone) {
        // TODO maybe give no error for "no Finder Info found"
        retval = ConvertError(result);
    }

    result = GetResponse(dib, readMsgNum);
    if (result != rsDone && retval == 0)
        retval = ConvertError(result);

    if (readResponse.DataLength != sizeof(AFPInfo) && retval == 0) {
        // TODO maybe just ignore it with no error?
        retval = networkError;
    }

    if (!VerifyBuffer(readResponse.DataOffset, readResponse.DataLength)
        && retval == 0)
        retval = networkError;

    memcpy(&afpInfo, (uint8_t*)&msg.smb2Header + readResponse.DataOffset,
        sizeof(AFPInfo));
    
    /* Do not use AFP info with bad signature or version */
    if (!AFPInfoValid(&afpInfo))
        InitAFPInfo();

    result = GetResponse(dib, closeMsgNum);
    if (result != rsDone && retval == 0) {
        // TODO give appropriate error code
        retval = ConvertError(result);
    }

    return retval;
}


/*
 * Does *info hold a valid AFP Info record?
 */
bool AFPInfoValid(AFPInfo *info) {
    return info->signature == AFPINFO_SIGNATURE
        && info->version == AFPINFO_VERSION;
}


/*
 * Initialize afpInfo to a "blank" but valid state.
 */
void InitAFPInfo(void) {
    memset(&afpInfo, 0, sizeof(AFPInfo));
    afpInfo.signature = AFPINFO_SIGNATURE;
    afpInfo.version = AFPINFO_VERSION;
    afpInfo.backupTime = 0x80000000; // indicating "never backed up"
}
