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
#include <memory.h>
#include <string.h>
#include <orca.h>
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
#include "helpers/closerequest.h"
#include "utils/finderstate.h"

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
    SMB2_QUERY_INFO_Request *queryInfoReq;
    uint16_t readMsgNum, queryInfoMsgNum, closeMsgNum;

    Word base, displacement, entryNum;
    
    uint32_t count;
    FILE_NAMES_INFORMATION *namesEntry;
    static FILE_DIRECTORY_INFORMATION dirEntry;
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
    
    uint16_t dirEntrySize;
    bool entryCached;
    int32_t cacheEntryNum;
    FILE_DIRECTORY_INFORMATION *entryPtr;
    FILE_DIRECTORY_INFORMATION *desiredEntry;
    uint16_t remainingSize;
    static char16_t nameBuf[SMB2_MAX_NAME_LEN * sizeof(char16_t)];

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
        fcr->dirEntryNum = 0;

        // Ensure next query will restart (needed for Linux ksmbd)
        fcr->nextServerEntryNum = INT32_MAX;

        if (fcr->dirCacheHandle != NULL) {
            DisposeHandle(fcr->dirCacheHandle);
            fcr->dirCacheHandle = NULL;
        }
        
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
    
    // Check if cache is valid, un-purged, and may contain desired entry
    if (fcr->dirCacheHandle != NULL) {
        HLock(fcr->dirCacheHandle);
        if (*fcr->dirCacheHandle == NULL
            || entryNum < fcr->firstCachedEntryNum) {
            DisposeHandle(fcr->dirCacheHandle);
            fcr->dirCacheHandle = NULL;
        }
    }

    if (dibs[i].flags & FLAG_AAPL_READDIR) {
        dirEntrySize = sizeof(FILE_ID_BOTH_DIR_INFORMATION);
    } else {
        dirEntrySize = sizeof(FILE_DIRECTORY_INFORMATION);
    }

    if (fcr->dirCacheHandle != NULL) {
        if (entryNum >= fcr->lastUsedCachedEntryNum) {
            cacheEntryNum = fcr->lastUsedCachedEntryNum;
            entryPtr = (void*)((char*)*fcr->dirCacheHandle
                + fcr->lastUsedCachedEntryOffset);
            remainingSize = GetHandleSize(fcr->dirCacheHandle)
                - fcr->lastUsedCachedEntryOffset;
        } else {
            cacheEntryNum = fcr->firstCachedEntryNum;
            entryPtr = (void*)*fcr->dirCacheHandle;
            remainingSize = GetHandleSize(fcr->dirCacheHandle);
        }

        entryCached = true;
        while (cacheEntryNum != entryNum) {
            if (entryPtr->NextEntryOffset == 0) {
                entryCached = false;
                DisposeHandle(fcr->dirCacheHandle);
                fcr->dirCacheHandle = NULL;
                break;
            }
            
            entryPtr = (void*)((char*)entryPtr + entryPtr->NextEntryOffset);
            remainingSize -= entryPtr->NextEntryOffset;
            cacheEntryNum++;
        }
    } else {
        entryCached = false;
    }
    
    if (entryCached) {
        desiredEntry = entryPtr;
        fcr->lastUsedCachedEntryNum = entryNum;
        fcr->lastUsedCachedEntryOffset = (char*)entryPtr - *fcr->dirCacheHandle;
    } else {    
        needRestart = entryNum < fcr->nextServerEntryNum;
        desiredEntry = NULL;
    
        do {
            if (dibs[i].flags & FLAG_AAPL_READDIR) {
                queryDirectoryRequest.FileInformationClass =
                    FileIdBothDirectoryInformation;
            } else {
                queryDirectoryRequest.FileInformationClass =
                    FileDirectoryInformation;
            }
            queryDirectoryRequest.Flags = 0;
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
            if (result != rsDone) {
                if (fcr->dirCacheHandle != NULL) {
                    DisposeHandle(fcr->dirCacheHandle);
                    fcr->dirCacheHandle = NULL;
                }
                if (result == rsFailed
                    && msg.smb2Header.Status == STATUS_NO_MORE_FILES) {
                    // Ensure next query will restart (needed for Linux ksmbd)
                    fcr->nextServerEntryNum = INT32_MAX;
                }
                return GDEError(result);
            }
    
            if (queryDirectoryResponse.OutputBufferLength > DIR_DATA_LENGTH(
                sizeof(msg.body) - sizeof(SMB2_QUERY_DIRECTORY_Response)))
                return networkError;
            if (!VerifyBuffer(queryDirectoryResponse.OutputBufferOffset,
                queryDirectoryResponse.OutputBufferLength))
                return networkError;

            fcr->firstCachedEntryNum = fcr->nextServerEntryNum;

            // Check that returned data is valid
            remainingSize = queryDirectoryResponse.OutputBufferLength;
            entryPtr = (FILE_DIRECTORY_INFORMATION *)((char*)&msg.smb2Header +
                queryDirectoryResponse.OutputBufferOffset);
            do {
                fcr->nextServerEntryNum++;
                if (remainingSize < dirEntrySize
                    || remainingSize - dirEntrySize < entryPtr->FileNameLength
                    || entryPtr->NextEntryOffset > remainingSize)
                    return networkError;
                
                if (fcr->nextServerEntryNum - 1 == entryNum)
                    desiredEntry = entryPtr;

                if (entryPtr->NextEntryOffset == 0) {
                    break;
                }

                remainingSize -= entryPtr->NextEntryOffset;
                entryPtr = (void*)((char*)entryPtr + entryPtr->NextEntryOffset);
            } while (1);
        } while (desiredEntry == NULL);
        
        // Cache the directory entries
        fcr->dirCacheHandle = NewHandle(
            queryDirectoryResponse.OutputBufferLength, userid(),
            attrLocked | attrNoSpec | attrPurge2, 0);
        if (toolerror()) {
            fcr->dirCacheHandle = NULL;
        } else {
            memcpy(*fcr->dirCacheHandle, (char*)&msg.smb2Header +
                queryDirectoryResponse.OutputBufferOffset,
                queryDirectoryResponse.OutputBufferLength);

            fcr->lastUsedCachedEntryNum = entryNum;
            fcr->lastUsedCachedEntryOffset =
                (char*)desiredEntry - (char*)&msg.smb2Header
                - queryDirectoryResponse.OutputBufferOffset;

            HUnlock(fcr->dirCacheHandle);
        }
    }

    /*
     * Save directory entry.
     * Note: The fixed fields of FILE_DIRECTORY_INFORMATION match the beginning
     * of FILE_ID_BOTH_DIR_INFORMATION_AAPL, so this works for both variants.
     */
    dirEntry = *desiredEntry;

    InitAFPInfo();

    if (dibs[i].flags & FLAG_AAPL_READDIR) {
        /*
         * Get directory information using Apple extensions.
         */
#define aaplDirEntry ((FILE_ID_BOTH_DIR_INFORMATION_AAPL *)desiredEntry)

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
        
        retval = SMBNameToGS(aaplDirEntry->FileName,
            aaplDirEntry->FileNameLength, pblock->name);

        if (fcr->dirCacheHandle != NULL)
            HUnlock(fcr->dirCacheHandle);
#undef aaplDirEntry
    } else {
        /*
         * Get directory information without using Apple extensions.
         */

        // Save file name to nameBuf
        if (dirEntry.FileNameLength > sizeof(nameBuf)) {
            if (fcr->dirCacheHandle != NULL)
                HUnlock(fcr->dirCacheHandle);
            return networkError;
        }
        memcpy(nameBuf, desiredEntry->FileName, desiredEntry->FileNameLength);
        
        if (fcr->dirCacheHandle != NULL)
            HUnlock(fcr->dirCacheHandle);

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
            memcpy(namePtr, nameBuf, dirEntry.FileNameLength);
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
            } else if (result != rsDone) {
                return GDEError(result);
            }
        
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
            
                readMsgNum = EnqueueRequest(&dibs[i], SMB2_READ,
                    sizeof(readRequest));
            }

            /*
             * Get stream information
             */
            queryInfoReq = (SMB2_QUERY_INFO_Request*)nextMsg->Body;
            // no need to check for space (any previous message is fixed-length)

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
        
            queryInfoMsgNum = EnqueueRequest(&dibs[i], SMB2_QUERY_INFO,
                sizeof(*queryInfoReq));
        
            /*
             * Close AFP Info ADS (or main stream, for redo)
             */
            closeMsgNum = EnqueueCloseRequest(&dibs[i], &fileID);
            // Cannot fail, because previous messages are fixed-length
            
            SendMessages(&dibs[i]);

            if (infoState == usingInfoStream) {
                result = GetResponse(&dibs[i], readMsgNum);
                if (result == rsFailed) {
                    // just ignore too-short AFP Info or other errors
                    goto handle_stream_info;
                } else if (result != rsDone) {
                    retval = GDEError(result);
                    goto handle_stream_info;
                }
            
                if (readResponse.DataLength != sizeof(AFPInfo)) {
                    retval = networkError;
                    goto handle_stream_info;
                }
            
                if (!VerifyBuffer(
                    readResponse.DataOffset,
                    readResponse.DataLength))
                {
                    retval = networkError;
                    goto handle_stream_info;
                }
            
                memcpy(&afpInfo,
                    (uint8_t*)&msg.smb2Header + readResponse.DataOffset,
                    sizeof(AFPInfo));
                
                /* Do not use AFP info with bad signature or version */
                if (!AFPInfoValid(&afpInfo))
                    InitAFPInfo();
            }

handle_stream_info:
            result = GetResponse(&dibs[i], queryInfoMsgNum);
            if (retval != 0) {
                // just ignore the response if we have an error already
                goto handle_close;
            } if (result == rsFailed) {
                /*
                 * Do not report errors about getting the resource fork size.
                 *
                 * If we are querying FileStreamInformation on the AFP Info
                 * stream, try again with the main stream instead.
                 * (Samba requires this.)
                 */
                if (infoState == usingInfoStream)
                    infoState = redoWithMainStream;
                goto handle_close;
            } else if (result != rsDone) {
                retval = GDEError(result);
                goto handle_close;
            }
        
            if (queryInfoResponse.OutputBufferLength >
                sizeof(msg.body) - offsetof(SMB2_QUERY_INFO_Response, Buffer)) {
                retval = networkError;
                goto handle_close;
            }
        
            if (!VerifyBuffer(
                queryInfoResponse.OutputBufferOffset,
                queryInfoResponse.OutputBufferLength)) {
                retval = networkError;
                goto handle_close;
            }
        
            streamInfoLen = queryInfoResponse.OutputBufferLength;
            streamInfo = (FILE_STREAM_INFORMATION *)(
                (unsigned char *)&msg.smb2Header +
                queryInfoResponse.OutputBufferOffset);
        
            while (streamInfoLen >= sizeof(FILE_STREAM_INFORMATION)) {
                if (streamInfo->NextEntryOffset > streamInfoLen) {
                    retval = networkError;
                    goto handle_close;
                }
                if (streamInfo->StreamNameLength >
                    streamInfoLen
                    - offsetof(FILE_STREAM_INFORMATION, StreamName)) {
                    retval = networkError;
                    goto handle_close;
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

handle_close:
            result = GetResponse(&dibs[i], closeMsgNum);
            if (result == rsFailed) {
                // ignore errors
            } else if (result != rsDone && retval != 0) {
                retval = GDEError(result);
            }
            
            if (retval)
                return retval;
        } while (infoState == redoWithMainStream);
        
        retval = SMBNameToGS(nameBuf, dirEntry.FileNameLength, pblock->name);
    }

    /*
     * Advance the entry number if we got to the stage of returning results,
     * even if we may still get an error about name/optionList buffer sizes.
     * This seems to be consistent with what other FSTs do.
     */
    fcr->dirEntryNum = entryNum;

    /*
     * Fill in results (name was done above)
     */
    if (haveResourceFork
        && !(dirEntry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        pblock->flags = isFileExtended;
    } else {
        pblock->flags = 0;
    }

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
        pblock->access = GetAccess(dirEntry.FileAttributes, &dibs[i]);

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

        /*
         * If this call is from Finder 6.0.1 - 6.0.3, adjust the reported
         * block sizes of very large files to prevent crashes or hangs when
         * Finder displays the Icon Info window.
         */
        if (pblock->blockCount + pblock->resourceBlocks
            > FINDER_601_MAX_DISPLAYABLE_BLOCKS
            && CallIsFromFinder(pblock, FINDER_600, FINDER_603)) {
            if (pblock->blockCount > FINDER_601_MAX_DISPLAYABLE_BLOCKS)
                pblock->blockCount = FINDER_601_MAX_DISPLAYABLE_BLOCKS;
            pblock->resourceBlocks =
                FINDER_601_MAX_DISPLAYABLE_BLOCKS - pblock->blockCount;
        }

        /*
         * Finder assumes that file names cannot exceed the 32-byte length
         * of its buffer, so it does not handle longer names correctly.
         * Finder assumes pblock->name->bufString.length is always <= 32.
         * If it is actually larger then Finder will wind up treating
         * data beyond the end of the buffer as part of the file name.
         * This causes it to display garbage at the end of the file name,
         * and if it encounters very long file names it can crash.
         *
         * To avoid these issues, we truncate longer file names being
         * returned to Finder, inserting an ellipsis for display purposes.
         * Finder will not know the true name of such files, so it will not
         * be able to open them or perform most other operations on them,
         * but at least they are displayed reasonably in Finder windows and
         * do not cause Finder crashes.
         */
        if (pblock->name->bufSize == 36 && pblock->name->bufString.length > 32
            && CallIsFromFinder(pblock, FINDER_600, FINDER_604)) {
            pblock->name->bufString.length = 32;
            pblock->name->bufString.text[31] = '\xC9';   /* ellipsis */
        }
    }}}}}}}}}}}}

    return retval;
}
