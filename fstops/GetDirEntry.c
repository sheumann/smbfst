#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <string.h>
#include "smb2/smb2.h"
#include "smb2/aapl.h"
#include "smb2/fileinfo.h"
#include "gsos/gsosdata.h"
#include "driver/driver.h"
#include "fst/fstspecific.h"
#include "helpers/path.h"
#include "helpers/errors.h"
#include "helpers/afpinfo.h"
#include "helpers/filetype.h"
#include "helpers/datetime.h"
#include "helpers/blocks.h"
#include "helpers/attributes.h"

#define NUMBER_OF_DOT_DIRS 2

/*
 * Standard File directory enumeration can infinite-loop if it gets an
 * invalidAccess error.  To avoid that, make sure not to give that error code.
 */
static Word GDEError(ReadStatus rs) {
    Word error = ConvertError(rs);
    return error == invalidAccess ? drvrIOError : error;
}

/*
 * macOS may sometimes send more data in a QUERY_DIRECTORY response than the
 * OutputBufferLength specified in the request.  It appears that it rounds
 * the specified length up to a multiple of 16K.  Also, [MS-SMB2] says that
 * Windows only supports lengths up to 64K.  So to avoid weirdness, we make
 * sure the requested length is exactly 16K, 32K, 48K, or 64K.
 */
#define DIR_DATA_LENGTH(x) (    \
    (x) >= 0x10000 ? 0x10000 :  \
    (x) >= 0xC000 ? 0xC000 :    \
    (x) >= 0x8000 ? 0x8000 :    \
    (x) >= 0x4000 ? 0x4000 : 0)

Word GetDirEntry(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;
    VirtualPointer vp;
    FCR *fcr;
    unsigned i;
    static SMB2_FILEID fileID;
    Word retval = 0;

    Word base, displacement, entryNum;
    
    uint32_t count;
    FILE_NAMES_INFORMATION *namesEntry;
    static FILE_DIRECTORY_INFORMATION dirEntry; 
    FILE_ID_BOTH_DIR_INFORMATION_AAPL *aaplDirEntry;
    uint16_t sizeLeft;
    bool needRestart;
    unsigned char *namePtr;
    unsigned nameLength;
    GSString *pathName;
    
    FILE_STREAM_INFORMATION *streamInfo;
    uint16_t streamInfoLen;
    bool haveResourceFork = false;
    static uint64_t resourceEOF, resourceAlloc;
    static FileType fileType;
    enum {usingInfoStream, redoWithMainStream, usingMainStream} infoState;

    vp = gsosdp->fcrPtr;
    DerefVP(fcr, vp);
    
    for (i = 0; i < NDIBS; i++) {
        if (dibs[i].DIBDevNum == gsosDP->dev1Num && dibs[i].extendedDIBPtr != 0)
            break;
    }
    if (i == NDIBS)
        return volNotFound;

    if (pcount == 0) {
        pblock = (void*)((char*)pblock - offsetof(DirEntryRecGS, refNum));
        pcount = 14;
    }
#define pblock ((DirEntryRecGS*)pblock)

    base = pblock->base;
    displacement = pblock->displacement;
    
    if (base == 0 && displacement == 0) {
        /*
         * Count directory entries
         */

        count = 0;
        fcr->nextServerEntryNum = -1;
        fcr->dirEntryNum = 0;
        
        do {
            queryDirectoryRequest.FileInformationClass = FileNamesInformation;
            
            if (count == 0) {
                queryDirectoryRequest.Flags = SMB2_RESTART_SCANS;
            } else {
                queryDirectoryRequest.Flags = 0;
            }
            
            queryDirectoryRequest.FileIndex = 0;
            queryDirectoryRequest.FileId = fcr->fileID;
            queryDirectoryRequest.FileNameOffset = sizeof(SMB2Header)
                + offsetof(SMB2_QUERY_DIRECTORY_Request, Buffer);
            queryDirectoryRequest.FileNameLength = sizeof(char16_t);
            queryDirectoryRequest.OutputBufferLength = DIR_DATA_LENGTH(
                sizeof(msg.body) - sizeof(SMB2_QUERY_DIRECTORY_Response));
        
            /* 
             * Note: [MS-SMB2] says the file name pattern is optional,
             * but Mac (at least) requires it.
             */
            ((char16_t*)queryDirectoryRequest.Buffer)[0] = '*';

            result = SendRequestAndGetResponse(&dibs[i], SMB2_QUERY_DIRECTORY,
                sizeof(queryDirectoryRequest)
                + queryDirectoryRequest.FileNameLength);
            if (result == rsFailed
                && msg.smb2Header.Status == STATUS_NO_MORE_FILES) {
                break;
            } else if (result != rsDone) {
                return ConvertError(result);
            }

            if (queryDirectoryResponse.OutputBufferLength > DIR_DATA_LENGTH(
                sizeof(msg.body) - sizeof(SMB2_QUERY_DIRECTORY_Response)))
                return networkError;
            if (!VerifyBuffer(queryDirectoryResponse.OutputBufferOffset,
                queryDirectoryResponse.OutputBufferLength))
                return networkError;
            
            sizeLeft = queryDirectoryResponse.OutputBufferLength;
            if (sizeLeft == 0)
                break;

            namesEntry = (FILE_NAMES_INFORMATION *)((char*)&msg.smb2Header
                + queryDirectoryResponse.OutputBufferOffset);

            do {
                if (sizeLeft < sizeof(FILE_NAMES_INFORMATION))
                    return networkError;
                count++;
                fcr->nextServerEntryNum++;
                
                if (namesEntry->NextEntryOffset == 0)
                    break;
                if (namesEntry->NextEntryOffset > sizeLeft)
                    return networkError;
                
                sizeLeft -= namesEntry->NextEntryOffset;
                namesEntry = (FILE_NAMES_INFORMATION *)
                    ((char*)namesEntry + namesEntry->NextEntryOffset);
            } while (1);

            if (count > 0xFFFFL + NUMBER_OF_DOT_DIRS)
                break;
        } while (queryDirectoryResponse.OutputBufferLength != 0);
        
        if (count < NUMBER_OF_DOT_DIRS)
            return networkError;
        
        // Don't count "." and ".."
        count -= NUMBER_OF_DOT_DIRS;
        
        pblock->entryNum = min(count, 0xFFFF);
        
        if (count > 0xFFFF)
            return outOfRange;
        
        return 0;
    }
    
    switch (base) {
    case 0x0000:
        entryNum = displacement;
        break;

    case 0x0001:
        entryNum = fcr->dirEntryNum + displacement;
        if (entryNum < fcr->dirEntryNum)
            return endOfDir;
        break;

    case 0x0002:
        if (displacement > fcr->dirEntryNum)
            return endOfDir;
        entryNum = fcr->dirEntryNum - displacement;
        break;
    }
    
    if (entryNum == 0)
        return endOfDir;
    
    needRestart = entryNum < fcr->nextServerEntryNum;

    do {
        if (dibs[i].flags & FLAG_AAPL_READDIR) {
            queryDirectoryRequest.FileInformationClass =
                FileIdBothDirectoryInformation;
        } else {
            queryDirectoryRequest.FileInformationClass =
                FileDirectoryInformation;
        }
        queryDirectoryRequest.Flags = SMB2_RETURN_SINGLE_ENTRY;
        if (needRestart) {
            queryDirectoryRequest.Flags |= SMB2_RESTART_SCANS;
            fcr->nextServerEntryNum = -1;
            needRestart = false;
        }
        queryDirectoryRequest.FileIndex = 0;
        queryDirectoryRequest.FileId = fcr->fileID;
        queryDirectoryRequest.FileNameOffset = sizeof(SMB2Header)
            + offsetof(SMB2_QUERY_DIRECTORY_Request, Buffer);
        queryDirectoryRequest.FileNameLength = sizeof(char16_t);
        queryDirectoryRequest.OutputBufferLength = DIR_DATA_LENGTH(
            sizeof(msg.body) - sizeof(SMB2_QUERY_DIRECTORY_Response));
    
        /* 
         * Note: [MS-SMB2] says the file name pattern is optional,
         * but Mac (at least) requires it.
         */
        ((char16_t*)queryDirectoryRequest.Buffer)[0] = '*';
    
        result = SendRequestAndGetResponse(&dibs[i], SMB2_QUERY_DIRECTORY,
            sizeof(queryDirectoryRequest)
            + queryDirectoryRequest.FileNameLength);
        if (result != rsDone)
            return GDEError(result);

        fcr->nextServerEntryNum++;

        if (queryDirectoryResponse.OutputBufferLength > DIR_DATA_LENGTH(
            sizeof(msg.body) - sizeof(SMB2_QUERY_DIRECTORY_Response)))
            return networkError;
        if (!VerifyBuffer(queryDirectoryResponse.OutputBufferOffset,
            queryDirectoryResponse.OutputBufferLength))
            return networkError;
        if (dibs[i].flags & FLAG_AAPL_READDIR) {
            if (queryDirectoryResponse.OutputBufferLength <
                sizeof(FILE_ID_BOTH_DIR_INFORMATION_AAPL))
                return networkError;
        } else {
            if (queryDirectoryResponse.OutputBufferLength <
                sizeof(FILE_DIRECTORY_INFORMATION))
                return networkError;
        }
    } while (entryNum != fcr->nextServerEntryNum - 1);

    /*
     * Save directory entry.
     * Note: The fixed fields of FILE_DIRECTORY_INFORMATION match the beginning
     * of FILE_ID_BOTH_DIR_INFORMATION_AAPL, so this works for both variants.
     */
    dirEntry = *(FILE_DIRECTORY_INFORMATION *)((char*)&msg.smb2Header +
        queryDirectoryResponse.OutputBufferOffset);
    if (dirEntry.FileNameLength > GBUF_SIZE)
        return networkError;

    InitAFPInfo();

    if (dibs[i].flags & FLAG_AAPL_READDIR) {
        /*
         * Get directory information using Apple extensions.
         */

        if (sizeof(FILE_ID_BOTH_DIR_INFORMATION_AAPL) + dirEntry.FileNameLength
            > queryDirectoryResponse.OutputBufferLength)
            return networkError;
        
        // Save file name to gbuf
        memcpy(gbuf, 
            (char*)&msg.smb2Header + queryDirectoryResponse.OutputBufferOffset
            + offsetof(FILE_ID_BOTH_DIR_INFORMATION_AAPL, FileName),
            dirEntry.FileNameLength);

        aaplDirEntry = (FILE_ID_BOTH_DIR_INFORMATION_AAPL *)(
            (char*)&msg.smb2Header + queryDirectoryResponse.OutputBufferOffset);

        resourceEOF = aaplDirEntry->RsrcForkLen;
        // TODO Maybe figure this out based on server allocation block size
        resourceAlloc = resourceEOF;
        
        /*
         * We don't have a "resource fork exists" flag, so we treat 0-length
         * resource forks as nonexistent.  This is consistent with the HFS
         * FST and at least some of the behavior of macOS.
         */
        haveResourceFork = resourceEOF != 0;

        /*
         * Expand compressed Finder Info into the AFP Info structure.
         * (windRect for directories corresponds to type+creator for files.)
         */
        afpInfo.finderInfo.windRect = 
            aaplDirEntry->CompressedFinderInfo.typeCreator;
        afpInfo.finderInfo.finderFlags =
            aaplDirEntry->CompressedFinderInfo.finderFlags;
        afpInfo.finderInfo.extFlags =
            aaplDirEntry->CompressedFinderInfo.extFlags;
        afpInfo.finderInfo.dateAdded =
            aaplDirEntry->CompressedFinderInfo.dateAdded;
    } else {
        /*
         * Get directory information without using Apple extensions.
         */

        if (sizeof(FILE_DIRECTORY_INFORMATION) + dirEntry.FileNameLength >
            queryDirectoryResponse.OutputBufferLength)
            return networkError;
        
        // Save file name to gbuf
        memcpy(gbuf, 
            (char*)&msg.smb2Header + queryDirectoryResponse.OutputBufferOffset
            + offsetof(FILE_DIRECTORY_INFORMATION, FileName),
            dirEntry.FileNameLength);

        haveResourceFork = false;
        resourceEOF = resourceAlloc = 0;
    
        infoState = usingInfoStream;
        do {
            if (infoState == redoWithMainStream)
                infoState = usingMainStream;
        
            /*
             * Open AFP Info ADS (or main stream, for redo)
             */
            createRequest.SecurityFlags = 0;
            createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
            createRequest.ImpersonationLevel = Impersonation;
            createRequest.SmbCreateFlags = 0;
            createRequest.Reserved = 0;
            if (infoState == usingInfoStream) {
                createRequest.DesiredAccess =
                    FILE_READ_DATA | FILE_READ_ATTRIBUTES;
            } else {
                createRequest.DesiredAccess = FILE_READ_ATTRIBUTES;
            }
            createRequest.FileAttributes = 0;
            createRequest.ShareAccess = FILE_SHARE_READ;
            createRequest.CreateDisposition = FILE_OPEN;
            createRequest.CreateOptions = 0; // TODO maybe FILE_NO_EA_KNOWLEDGE
            createRequest.NameOffset =
                sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
            createRequest.CreateContextsOffset = 0;
            createRequest.CreateContextsLength = 0;
        
            // translate file path to SMB format (directory\file)
            vp = fcr->pathName;
            DerefVP(pathName, vp);
            namePtr = createRequest.Buffer;
#define NAME_SPACE (((char*)msg.body + sizeof(msg.body)) - (char*)namePtr)
            
            nameLength =
                GSPathToSMB(pathName, createRequest.Buffer, NAME_SPACE);
            if (nameLength == 0xFFFF)
                return badPathSyntax;    
            namePtr += nameLength;
        
            if (nameLength != 0) {
                if (NAME_SPACE < sizeof(char16_t))
                    return badPathSyntax;
                *(char16_t*)namePtr = '\\';
                namePtr += sizeof(char16_t);
            }
        
            if (NAME_SPACE < dirEntry.FileNameLength)
                return badPathSyntax;
            memcpy(namePtr, gbuf, dirEntry.FileNameLength);
            namePtr += dirEntry.FileNameLength;
        
            if (infoState == usingInfoStream) {
                if (NAME_SPACE < sizeof(afpInfoSuffix))
                    return badPathSyntax;
                memcpy(namePtr, afpInfoSuffix, sizeof(afpInfoSuffix));
                namePtr += sizeof(afpInfoSuffix);
            }
        
            createRequest.NameLength = namePtr - createRequest.Buffer;
            
            result = SendRequestAndGetResponse(&dibs[i], SMB2_CREATE,
                sizeof(createRequest) + createRequest.NameLength);
            if (result == rsFailed) {
                /*
                 * We ignore errors related to accessing the AFP Info or
                 * resource fork and just behave like they don't exist.
                 * Giving an error might terminate the whole directory listing,
                 * which generally isn't desirable.
                 *
                 * If we get an error accessing the AFP Info, we try again to
                 * access the resource fork information via the main stream.
                 * This can come up for files created by macOS on a 
                 * Samba/Windows server, which may have a resource fork but no
                 * AFP Info.
                 */
                // TODO maybe add an option to skip the extra resource fork check
                // (This situation should not come up if using only the SMB FST.)
                if (infoState == usingInfoStream) {
                    InitAFPInfo();
                    infoState = redoWithMainStream;
                    continue;
                } else {
                    break;
                }
            } else if (result != rsDone)
                return GDEError(result);
        
            fileID = createResponse.FileId;
        
            if (infoState == usingInfoStream) {
                /*
                 * Read AFP Info
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
            
                result = SendRequestAndGetResponse(&dibs[i], SMB2_READ,
                    sizeof(readRequest));
                if (result == rsFailed) {
                    // just ignore too-short AFP Info or other errors
                    goto get_stream_info;
                } else if (result != rsDone) {
                    retval = GDEError(result);
                    goto close_stream;
                }
            
                if (readResponse.DataLength != sizeof(AFPInfo)) {
                    retval = networkError;
                    goto close_stream;
                }
            
                if (!VerifyBuffer(
                    readResponse.DataOffset,
                    readResponse.DataLength))
                {
                    retval = networkError;
                    goto close_stream;
                }
            
                memcpy(&afpInfo,
                    (uint8_t*)&msg.smb2Header + readResponse.DataOffset,
                    sizeof(AFPInfo));
                
                /* Do not use AFP info with bad signature or version */
                if (!AFPInfoValid(&afpInfo))
                    InitAFPInfo();
            }
    
get_stream_info:    
            /*
             * Get stream information
             */
            queryInfoRequest.InfoType = SMB2_0_INFO_FILE;
            queryInfoRequest.FileInfoClass = FileStreamInformation;
            queryInfoRequest.OutputBufferLength =
                sizeof(msg.body) - offsetof(SMB2_QUERY_INFO_Response, Buffer);
            queryInfoRequest.InputBufferOffset = 0;
            queryInfoRequest.Reserved = 0;
            queryInfoRequest.InputBufferLength = 0;
            queryInfoRequest.AdditionalInformation = 0;
            queryInfoRequest.Flags = 0;
            queryInfoRequest.FileId = fileID;
        
            result = SendRequestAndGetResponse(&dibs[i], SMB2_QUERY_INFO,
                sizeof(queryInfoRequest));
            if (result == rsFailed) {
                /*
                 * Do not report errors about getting the resource fork size.
                 *
                 * If we are querying FileStreamInformation on the AFP Info
                 * stream, try again with the main stream instead.
                 * (Samba requires this.)
                 */
                if (infoState == usingInfoStream)
                    infoState = redoWithMainStream;
                goto close_stream;
            } else if (result != rsDone) {
                retval = GDEError(result);
                goto close_stream;
            }
        
            if (queryInfoResponse.OutputBufferLength >
                sizeof(msg.body) - offsetof(SMB2_QUERY_INFO_Response, Buffer)) {
                retval = networkError;
                goto close_stream;
            }
        
            if (!VerifyBuffer(
                queryInfoResponse.OutputBufferOffset,
                queryInfoResponse.OutputBufferLength)) {
                retval = networkError;
                goto close_stream;
            }
        
            streamInfoLen = queryInfoResponse.OutputBufferLength;
            streamInfo = (FILE_STREAM_INFORMATION *)(
                (unsigned char *)&msg.smb2Header +
                queryInfoResponse.OutputBufferOffset);
        
            while (streamInfoLen >= sizeof(FILE_STREAM_INFORMATION)) {
                if (streamInfo->NextEntryOffset > streamInfoLen) {
                    retval = networkError;
                    goto close_stream;
                }
                if (streamInfo->StreamNameLength >
                    streamInfoLen
                    - offsetof(FILE_STREAM_INFORMATION, StreamName)) {
                    retval = networkError;
                    goto close_stream;
                }
        
                if (streamInfo->StreamNameLength == sizeof(resourceForkSuffix)
                    && memcmp(streamInfo->StreamName, resourceForkSuffix,
                        sizeof(resourceForkSuffix)) == 0)
                {
                    haveResourceFork = true;
                    resourceEOF = streamInfo->StreamSize;
                    resourceAlloc = streamInfo->StreamAllocationSize;
                    break;
                }
        
                if (streamInfo->NextEntryOffset == 0)
                    break;
                streamInfoLen -= streamInfo->NextEntryOffset;
                streamInfo =
                    (void*)((char*)streamInfo + streamInfo->NextEntryOffset);
            }
        
            /*
             * Close AFP Info ADS (or main stream, for redo)
             */
close_stream:
            closeRequest.Flags = 0;
            closeRequest.Reserved = 0;
            closeRequest.FileId = fileID;
        
            result = SendRequestAndGetResponse(&dibs[i], SMB2_CLOSE,
                sizeof(closeRequest));
            if (result == rsFailed) {
                // ignore errors
            } else if (result != rsDone) {
                return retval ? retval : GDEError(result);
            }
            
            if (retval)
                return retval;
        } while (infoState == redoWithMainStream);
    }

    /*
     * Advance the entry number if we got to the stage of returning results,
     * even if we may still get an error about name/optionList buffer sizes.
     * This seems to be consistent with what other FSTs do.
     */
    fcr->dirEntryNum = entryNum;

    /*
     * Fill in results
     */
    if (haveResourceFork
        && !(dirEntry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        pblock->flags = isFileExtended;
    } else {
        pblock->flags = 0;
    }

    retval =
        SMBNameToGS((char16_t*)gbuf, dirEntry.FileNameLength, pblock->name);

    if (pcount >= 6) {
        pblock->entryNum = entryNum;
    
    if (pcount >= 7) {
        fileType = GetFileType(&pblock->name->bufString, &afpInfo,
            (bool)(dirEntry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY));
        pblock->fileType = fileType.fileType;
    
    if (pcount >= 8) {
        pblock->eof = min(dirEntry.EndOfFile, 0xFFFFFFFF);
    
    if (pcount >= 9) {
        pblock->blockCount = GetBlockCount(dirEntry.AllocationSize);

    if (pcount >= 10) {
        pblock->createDateTime =
            GetGSTime(dirEntry.CreationTime, dibs[i].session);

    if (pcount >= 11) {
        pblock->modDateTime =
            GetGSTime(dirEntry.LastWriteTime, dibs[i].session);

    if (pcount >= 12) {
        pblock->access = GetAccess(dirEntry.FileAttributes);

    if (pcount >= 13) {
        pblock->auxType = fileType.auxType;

    if (pcount >= 14) {
        pblock->fileSysID = smbFSID;
    
    if (pcount >= 15) {
        if (pblock->optionList != NULL) {
            // TODO Maybe don't return Finder Info when it's not available
            if (pblock->optionList->bufSize < 4) {
                if (!retval)
                    retval = paramRangeErr;
            } else {
                pblock->optionList->bufString.length =
                    sizeof(FinderInfo) + 2;
                if (pblock->optionList->bufSize < sizeof(FinderInfo) + 6) {
                    if (!retval)
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

    if (pcount >= 16) {    
        pblock->resourceEOF = resourceEOF;

    if (pcount >= 17) {
        pblock->resourceBlocks = GetBlockCount(resourceAlloc);
    }}}}}}}}}}}}

    return retval;
}
