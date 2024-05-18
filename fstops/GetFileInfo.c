#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <uchar.h>
#include <stddef.h>
#include <string.h>
#include "smb2/smb2.h"
#include "gsos/gsosutils.h"
#include "helpers/path.h"
#include "helpers/attributes.h"
#include "helpers/blocks.h"
#include "helpers/datetime.h"
#include "helpers/afpinfo.h"
#include "helpers/filetype.h"
#include "helpers/closerequest.h"
#include "fstops/GetFileInfo.h"
#include "helpers/errors.h"

FILE_BASIC_INFORMATION basicInfo;
bool haveDataForkSizes;
uint64_t dataEOF, dataAlloc;
bool isRootDir;

/*
 * This contains the implementation of GetFileInfo, which is also used when
 * getting the same information in an Open call.
 *
 * When used for Open, alreadyOpen is set to true, fileID is provided, and
 * pblock is adjusted to line up corresponding fields (access through 
 * resourceBlocks).  In addition, the CreationTime, LastWriteTime, and
 * FileAttributes fields of basicInfo must be pre-filled in this case,
 * haveDataForkSizes must be set to indicate whether dataEOF and dataAlloc
 * have been filled in with the sizes for the data fork, and isRootDir must
 * be set to indicate whether the file is the root directory of a share.
 */
Word GetFileInfo_Impl(void *pblock, struct GSOSDP *gsosdp, Word pcount,
    bool alreadyOpen, SMB2_FILEID fileID) {

    ReadStatus result;
    DIB *dib;
    Word retval = 0;
    FILE_STREAM_INFORMATION *streamInfo;
    uint16_t streamInfoLen;
    bool haveAFPInfo = false;
    bool haveResourceFork = false;

    static uint64_t resourceEOF, resourceAlloc;
    static FileType fileType;
    
    static ProDOSTime pdosTime;

    static uint16_t createMsgNum, queryInfoMsgNum, closeMsgNum;
    SMB2_QUERY_INFO_Request *queryInfoReq;

    dib = GetDIB(gsosdp, 1);
    if (dib == NULL)
        return volNotFound;

top:
    resourceEOF = resourceAlloc = 0;

    if (!alreadyOpen) {
        /*
         * Open file
         */
        createRequest.SecurityFlags = 0;
        createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
        createRequest.ImpersonationLevel = Impersonation;
        createRequest.SmbCreateFlags = 0;
        createRequest.Reserved = 0;
        createRequest.DesiredAccess = FILE_READ_ATTRIBUTES;
        createRequest.FileAttributes = 0;
        createRequest.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
        createRequest.CreateDisposition = FILE_OPEN;
        createRequest.CreateOptions = 0;
        createRequest.NameOffset =
            sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
        createRequest.CreateContextsOffset = 0;
        createRequest.CreateContextsLength = 0;
    
        // translate filename to SMB format
        createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1,
            createRequest.Buffer,
            sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
        if (createRequest.NameLength == 0xFFFF)
            return badPathSyntax;
        isRootDir = createRequest.NameLength == 0;
    
        createMsgNum = EnqueueRequest(dib, SMB2_CREATE,
            sizeof(createRequest) + createRequest.NameLength);

        fileID = fileIDFromPrevious;
    }

    if (pcount != 2) {  // Skip remaining queries if we only need access word
        /*
         * Get stream information
         */
        queryInfoReq = (SMB2_QUERY_INFO_Request*)nextMsg->Body;
        if (!SpaceAvailable(sizeof(*queryInfoReq)))
            return fstError;
        
        queryInfoReq->InfoType = SMB2_0_INFO_FILE;
        queryInfoReq->FileInfoClass = FileStreamInformation;
        queryInfoReq->OutputBufferLength =
            sizeof(msg.body) - offsetof(SMB2_QUERY_INFO_Response, Buffer);
        queryInfoReq->InputBufferOffset = 0;
        queryInfoReq->Reserved = 0;
        queryInfoReq->InputBufferLength = 0;
        queryInfoReq->AdditionalInformation = 0;
        queryInfoReq->Flags = 0;
        queryInfoReq->FileId = fileID;
    
        queryInfoMsgNum = EnqueueRequest(dib, SMB2_QUERY_INFO,
            sizeof(*queryInfoReq));
    }

    if (!alreadyOpen) {
        /*
         * Close file
         */    
        closeMsgNum = EnqueueCloseRequest(dib, &fileID);
        if (closeMsgNum == 0xFFFF)
            return fstError;
    }

    if (!alreadyOpen || pcount != 2)
        SendMessages(dib);

    if (!alreadyOpen) {
        /* Handle CREATE response */
        result = GetResponse(dib, createMsgNum);
        if (result != rsDone) {
            retval = ConvertError(result);
        } else {
            basicInfo.CreationTime = createResponse.CreationTime;
            basicInfo.LastWriteTime = createResponse.LastWriteTime;
            basicInfo.FileAttributes = createResponse.FileAttributes;
            
            dataEOF = createResponse.EndofFile;
            dataAlloc = createResponse.AllocationSize;
            haveDataForkSizes = true;
        }
    }

    if (pcount != 2) {
        /* Handle QUERY_INFO response */
        result = GetResponse(dib, queryInfoMsgNum);
        if (result != rsDone) {
            /*
             * macOS and Samba will not let us query FileStreamInformation on
             * a resource fork.  To work around this, we will go back and open
             * the data fork if we hit this error.
             */
            if (alreadyOpen
                && !haveDataForkSizes
                && result == rsFailed
                && (msg.smb2Header.Status == STATUS_ACCESS_DENIED
                    || msg.smb2Header.Status == STATUS_INVALID_PARAMETER)) {
                alreadyOpen = false;
                goto top;
            }
            /*
             * STATUS_INVALID_PARAMETER presumably means that we cannot get
             * stream information because named streams are not supported (e.g.
             * on Windows serving a FAT filesystem).  Just act like AFP Info &
             * resource fork are not available, but don't treat this as an
             * error.
             */
            if (result == rsFailed
                && msg.smb2Header.Status == STATUS_INVALID_PARAMETER
                && haveDataForkSizes) {
                // do nothing
            } else if (retval == 0) {
                retval = ConvertError(result);
            }
            goto handle_close;
        }
        
        if (queryInfoResponse.OutputBufferLength >
            sizeof(msg.body) - offsetof(SMB2_QUERY_INFO_Response, Buffer)) {
            if (retval == 0)
                retval = networkError;
            goto handle_close;
        }
    
        if (!VerifyBuffer(
            queryInfoResponse.OutputBufferOffset,
            queryInfoResponse.OutputBufferLength)) {
            if (retval == 0)
                retval = networkError;
            goto handle_close;
        }
    
        streamInfoLen = queryInfoResponse.OutputBufferLength;
        streamInfo = (FILE_STREAM_INFORMATION *)((char *)&msg.smb2Header +
            queryInfoResponse.OutputBufferOffset);
    
        while (streamInfoLen >= sizeof(FILE_STREAM_INFORMATION)) {
            if (streamInfo->NextEntryOffset > streamInfoLen) {
                if (retval == 0)
                    retval = networkError;
                goto handle_close;
            }
            if (streamInfo->StreamNameLength >
                streamInfoLen - offsetof(FILE_STREAM_INFORMATION, StreamName)) {
                if (retval == 0)
                    retval = networkError;
                goto handle_close;
            }
    
            if (streamInfo->StreamNameLength == 7*2 &&
                memcmp(streamInfo->StreamName, u"::$DATA", 7*2) == 0)
            {
                /*
                 * We use the EOF/allocation size from the CREATE response if
                 * they are available and still valid, and if the server claims
                 * the data fork allocation size is equal to its EOF.  The
                 * reason is that macOS reports the true allocation size in the
                 * CREATE response, but not in FILE_STREAM_INFORMATION.
                 */
                if (streamInfo->StreamSize != streamInfo->StreamAllocationSize
                    || !haveDataForkSizes
                    || streamInfo->StreamSize != dataEOF) {
                    dataEOF = streamInfo->StreamSize;
                    dataAlloc = streamInfo->StreamAllocationSize;
                    haveDataForkSizes = true;
                }
            }
            else if (streamInfo->StreamNameLength == sizeof(resourceForkSuffix)
                && memcmp(streamInfo->StreamName, resourceForkSuffix,
                    sizeof(resourceForkSuffix)) == 0)
            {
                haveResourceFork = true;
                resourceEOF = streamInfo->StreamSize;
                resourceAlloc = streamInfo->StreamAllocationSize;
            }
            else if (streamInfo->StreamNameLength == sizeof(afpInfoSuffix) &&
                memcmp(streamInfo->StreamName, afpInfoSuffix,
                    sizeof(afpInfoSuffix)) == 0 &&
                streamInfo->StreamSize >= sizeof(AFPInfo))
            {
                haveAFPInfo = true;
            }
    
            if (streamInfo->NextEntryOffset == 0)
                break;
            streamInfoLen -= streamInfo->NextEntryOffset;
            streamInfo =
                (void*)((char*)streamInfo + streamInfo->NextEntryOffset);
        }
        
        if (!haveDataForkSizes)
            dataEOF = dataAlloc = 0;
    }

handle_close:
    if (!alreadyOpen) {
        /* Handle CLOSE response */
        result = GetResponse(dib, closeMsgNum);
        if (result != rsDone)
            return retval ? retval : ConvertError(result);
    }

    if (haveAFPInfo && retval == 0) {
        retval = GetAFPInfo(dib, gsosdp);
    } else {
        InitAFPInfo();
        // TODO set type/creator code?
    }

    if (retval != 0)
        return retval;

    if (pcount == 0) {
        #define pblock ((FileRec*)pblock)
        
        pblock->fAccess = GetAccess(basicInfo.FileAttributes, dib);
        if (isRootDir)
            pblock->fAccess &= ~renameEnable;
        
        fileType = GetFileType(gsosdp->path1Ptr, &afpInfo,
            (bool)(basicInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY));
        pblock->fileType = fileType.fileType;
        pblock->auxType = fileType.auxType;

        if (basicInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            pblock->storageType = directoryFile;
        } else if (haveResourceFork) {
            pblock->storageType = extendedFile;
        } else {
            pblock->storageType = standardFile;
        }
        
        pdosTime = GetProDOSTime(basicInfo.CreationTime, dib->session);
        pblock->createDate = pdosTime.date;
        pblock->createTime = pdosTime.time;
        
        pdosTime = GetProDOSTime(basicInfo.LastWriteTime, dib->session);
        pblock->modDate = pdosTime.date;
        pblock->modTime = pdosTime.time;
        
        pblock->blocksUsed = GetBlockCount(dataAlloc);
        
        #undef pblock
    } else {
        #define pblock ((FileInfoRecGS*)pblock)
        
        pblock->access = GetAccess(basicInfo.FileAttributes, dib);
        if (isRootDir)
            pblock->access &= ~renameEnable;
        
        if (pcount >= 3) {
            fileType = GetFileType(gsosdp->path1Ptr, &afpInfo,
                (bool)(basicInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY));
            pblock->fileType = fileType.fileType;

        if (pcount >= 4) {
            pblock->auxType = fileType.auxType;

        if (pcount >= 5) {
            if (basicInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                pblock->storageType = directoryFile;
            } else if (haveResourceFork) {
                pblock->storageType = extendedFile;
            } else {
                pblock->storageType = standardFile;
            }

        if (pcount >= 6) {
            pblock->createDateTime =
                GetGSTime(basicInfo.CreationTime, dib->session);

        if (pcount >= 7) {
            pblock->modDateTime =
                GetGSTime(basicInfo.LastWriteTime, dib->session);

        if (pcount >= 8) {
            if (pblock->optionList != NULL) {
                if (pblock->optionList->bufSize < 4) {
                    retval = paramRangeErr;
                } else {
                    pblock->optionList->bufString.length =
                        sizeof(FinderInfo) + 2;
                    if (pblock->optionList->bufSize < sizeof(FinderInfo) + 6) {
                        retval = buffTooSmall;
                    } else {
                        /*
                         * Return Finder Info in option list. Use HFS FSID
                         * so that ProDOS/HFS/AppleShare FSTs will accept it.
                         */
                        *(Word*)pblock->optionList->bufString.text = hfsFSID;
                        memcpy(pblock->optionList->bufString.text + 2,
                            &afpInfo.finderInfo, sizeof(FinderInfo));
                    }
                }
            }

        if (pcount >= 9) {
            pblock->eof = min(dataEOF, 0xffffffff);

        if (pcount >= 10) {
            pblock->blocksUsed = GetBlockCount(dataAlloc);

        if (pcount >= 11) {
            pblock->resourceEOF = min(resourceEOF, 0xffffffff);

        if (pcount >= 12) {
            pblock->resourceBlocks = GetBlockCount(resourceAlloc);
        }}}}}}}}}}

        #undef pblock
    }
    
    return retval;
}

Word GetFileInfo(void *pblock, void *gsosdp, Word pcount) {
    static const SMB2_FILEID fileID_0 = {0};
    return GetFileInfo_Impl(pblock, gsosdp, pcount, false, fileID_0);
}

