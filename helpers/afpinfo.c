#include "defs.h"
#include <string.h>
#include <gsos.h>
#include "smb2.h"
#include "path.h"
#include "helpers/afpinfo.h"

AFPInfo afpInfo;

static char16_t finderInfoSuffix[18] = u":AFP_AfpInfo:$DATA";

Word GetFinderInfo(DIB *dib, struct GSOSDP *gsosdp) {
    ReadStatus result;
    SMB2_FILEID fileID;
    Word retval = 0;
    
    memset(&afpInfo, 0, sizeof(AFPInfo));

    /*
     * Open Finder Info ADS
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
    createRequest.NameLength = GSPathToSMB(gsosdp, 1, createRequest.Buffer,
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
    if (createRequest.NameLength == 0xFFFF)
        return badPathSyntax;

    if (createRequest.NameLength >
        sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer)
        - sizeof(finderInfoSuffix))
        return badPathSyntax;

    memcpy(createRequest.Buffer + createRequest.NameLength,
        finderInfoSuffix, sizeof(finderInfoSuffix));
    createRequest.NameLength += sizeof(finderInfoSuffix);
    
    result = SendRequestAndGetResponse(dib->session, SMB2_CREATE, dib->treeId,
        sizeof(createRequest) + createRequest.NameLength);
    if (result != rsDone) {
        // TODO give appropriate error code (maybe none for no Finder Info)
        return networkError;
    }
    
    fileID = createResponse.FileId;

    /*
     * Read Finder Info
     */
    readRequest.Padding =
        sizeof(SMB2Header) + offsetof(SMB2_READ_Response, Buffer);
    readRequest.Flags = 0;
    readRequest.Length = sizeof(AFPInfo);
    readRequest.Offset = 0;
    readRequest.FileId = fileID;
    readRequest.MinimumCount = sizeof(AFPInfo);
    readRequest.Channel = 0;
    readRequest.RemainingBytes = 0;
    readRequest.ReadChannelInfoOffset = 0;
    readRequest.ReadChannelInfoLength = 0;

    result = SendRequestAndGetResponse(dib->session, SMB2_READ,
        dib->treeId, sizeof(readRequest));
    if (result != rsDone) {
        // TODO give appropriate error code
        retval = networkError;
        goto close;
    }

    if (readResponse.DataLength != sizeof(AFPInfo)) {
        // TODO give appropriate error code
        retval = networkError;
        goto close;
    }

    if (!VerifyBuffer(readResponse.DataOffset, readResponse.DataLength)) {
        // TODO give appropriate error code
        retval = networkError;
        goto close;
    }

    memcpy(&afpInfo, (uint8_t*)&msg.smb2Header + readResponse.DataOffset,
        sizeof(AFPInfo));
    
    /* Do not use AFP info with bad signature or version */
    if (afpInfo.signature != AFPINFO_SIGNATURE
        || afpInfo.version != AFPINFO_VERSION) {
        memset(&afpInfo, 0, sizeof(AFPInfo));
    }

    /*
     * Close Finder Info ADS
     */
close:
    closeRequest.Flags = 0;
    closeRequest.Reserved = 0;
    closeRequest.FileId = fileID;

    result = SendRequestAndGetResponse(dib->session, SMB2_CLOSE, dib->treeId,
        sizeof(closeRequest));
    if (result != rsDone) {
        // TODO give appropriate error code
        return retval ? retval : networkError;
    }

    return retval;
}
