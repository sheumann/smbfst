#include "defs.h"
#include <gsos.h>
#include <prodos.h>
#include <stdint.h>
#include <string.h>
#include "smb2/smb2.h"
#include "fst/fstspecific.h"
#include "smb2/fileinfo.h"
#include "driver/driver.h"
#include "gsos/gsosutils.h"
#include "helpers/path.h"
#include "helpers/attributes.h"
#include "helpers/filetype.h"
#include "helpers/datetime.h"
#include "helpers/errors.h"
#include "helpers/closerequest.h"

Word SetFileInfo(void *pblock, struct GSOSDP *gsosdp, Word pcount) {
    ReadStatus result;
    DIB *dib;
    static SMB2_FILEID fileID, infoFileID;
    Word retval = 0;

    uint32_t attributes, originalAttributes;
    FileType fileType = {0,0};
    static FileType originalFileType;
    static uint64_t createDate, modDate;
    
    Word access;
    static ProDOSTime prodosTime;
    static TypeCreator typeCreator;
    bool needSpecificCreator;
    bool infoValid;
    bool forcedWritable = false;
    unsigned tryNum;
    Word fsid;
    bool haveFinderInfo;
    
    createDate = modDate = 0;

    dib = GetDIB(gsosdp, 1);
    if (dib == NULL)
        return volNotFound;

    if (pcount == 0) {
        #define pblock ((FileRec*)pblock)
        
        access = pblock->fAccess;
        fileType.fileType = pblock->fileType;
        fileType.auxType = pblock->auxType;
        
        if (pblock->createDate != 0 || pblock->createTime != 0) {
            prodosTime.date = pblock->createDate;
            prodosTime.time = pblock->createTime;
            createDate = ProDOSTimeToFiletime(prodosTime, dib->session);
        }
        
        if (pblock->modDate != 0 || pblock->modTime != 0) {
            prodosTime.date = pblock->modDate;
            prodosTime.time = pblock->modTime;
            modDate = ProDOSTimeToFiletime(prodosTime, dib->session);
        } else {
            modDate = CurrentTime(dib->session);
        }
        
        #undef pblock
    } else {
        #define pblock ((FileInfoRecGS*)pblock)

        access = pblock->access;
        
        if (pcount >= 3) {
            fileType.fileType = pblock->fileType;
        
        if (pcount >= 4) {
            fileType.auxType = pblock->auxType;
        
        if (pcount >= 6) {
            if (*(uint64_t*)&pblock->createDateTime != 0)
                createDate =
                    GSTimeToFiletime(pblock->createDateTime, dib->session);

        if (pcount >= 7) {
            if (*(uint64_t*)&pblock->modDateTime != 0) {
                modDate = GSTimeToFiletime(pblock->modDateTime, dib->session);
            } else {
                modDate = CurrentTime(dib->session);
            }
        
            // optionList is handled below
        }}}}
        
        #undef pblock
    }

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
    
    // compute revised attributes
    attributes = originalAttributes = createResponse.FileAttributes;
    attributes &= ~(uint32_t)(
        FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | 
        FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL);
    attributes |= 
        GetFileAttributes(access, attributes & FILE_ATTRIBUTE_DIRECTORY, dib)
        & ~(uint32_t)FILE_ATTRIBUTE_NORMAL;
    if (attributes == 0)
        attributes = FILE_ATTRIBUTE_NORMAL;

    if (attributes & FILE_ATTRIBUTE_DIRECTORY)
        fileType.fileType = DIRECTORY_FILETYPE;

    if (pcount == 0 || pcount >= 3) {
        if (createResponse.FileAttributes & FILE_ATTRIBUTE_READONLY) {
            /*
             * Make file writable (for now) so that we can write AFP Info.
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
            info->FileAttributes =
                attributes & ~(uint32_t)FILE_ATTRIBUTE_READONLY;
            if (info->FileAttributes == 0)
                info->FileAttributes = FILE_ATTRIBUTE_NORMAL;
            info->Reserved = 0;
#undef info
        
            result = SendRequestAndGetResponse(dib, SMB2_SET_INFO,
                sizeof(setInfoRequest) + sizeof(FILE_BASIC_INFORMATION));
            // ignore errors here

            forcedWritable = true;
        }

        /*
         * Open AFP Info ADS.
         * (We try to get read/write access, but proceed with less if we fail.)
         */
        for (tryNum = 0; tryNum < 3; tryNum++) {
            createRequest.SecurityFlags = 0;
            createRequest.RequestedOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
            createRequest.ImpersonationLevel = Impersonation;
            createRequest.SmbCreateFlags = 0;
            createRequest.Reserved = 0;
            createRequest.FileAttributes = 0;
            createRequest.ShareAccess = 0;
            createRequest.CreateDisposition = FILE_OPEN_IF;
            createRequest.CreateOptions = 0;
            createRequest.NameOffset =
                sizeof(SMB2Header) + offsetof(SMB2_CREATE_Request, Buffer);
            createRequest.CreateContextsOffset = 0;
            createRequest.CreateContextsLength = 0;
        
            // translate filename to SMB format
            createRequest.NameLength = GSOSDPPathToSMB(gsosdp, 1,
                createRequest.Buffer,
                sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer));
            if (createRequest.NameLength == 0xFFFF) {
                retval = badPathSyntax;
                goto finish;
            }
        
            if (createRequest.NameLength >
                sizeof(msg.body) - offsetof(SMB2_CREATE_Request, Buffer)
                - sizeof(afpInfoSuffix)) {
                retval = badPathSyntax;
                goto finish;
            }
        
            memcpy(createRequest.Buffer + createRequest.NameLength,
                afpInfoSuffix, sizeof(afpInfoSuffix));
            createRequest.NameLength += sizeof(afpInfoSuffix);

            if (tryNum == 0) {
                createRequest.DesiredAccess = FILE_READ_DATA | FILE_WRITE_DATA;
            } else if (tryNum == 1) {
                createRequest.DesiredAccess = FILE_WRITE_DATA;
            } else {
                createRequest.DesiredAccess = FILE_READ_DATA;
            }

            result = SendRequestAndGetResponse(dib, SMB2_CREATE,
                sizeof(createRequest) + createRequest.NameLength);
            if (result == rsDone)
                break;
            /*
             * If we get STATUS_OBJECT_NAME_INVALID for the AFP info (after
             * successfully accessing the main stream with the same base name),
             * this presumably means that the filesystem does not support
             * named streams.  We will not report this as an error, because
             * if we did it would prevent us from setting file info on such
             * filesystems at all.  This way, we can at least set attributes
             * and dates, although the filetype and Finder Info will not be
             * set correctly.
             */
            if (result == rsFailed
                && msg.smb2Header.Status == STATUS_OBJECT_NAME_INVALID)
                goto finish;
        }
        if (result != rsDone) {
            retval = ConvertError(result);
            goto finish;
        }
        
        infoFileID = createResponse.FileId;
        
        if (createResponse.CreateAction != FILE_CREATED) {
            /*
             * Read AFP Info, if possible
             */
            readRequest.Padding =
                sizeof(SMB2Header) + offsetof(SMB2_READ_Response, Buffer);
            readRequest.Flags = 0;
            readRequest.Length = sizeof(AFPInfo);
            readRequest.Offset = 0;
            readRequest.FileId = infoFileID;
            readRequest.MinimumCount = sizeof(AFPInfo);
            readRequest.Channel = 0;
            readRequest.RemainingBytes = 0;
            readRequest.ReadChannelInfoOffset = 0;
            readRequest.ReadChannelInfoLength = 0;
        
            result = SendRequestAndGetResponse(dib, SMB2_READ,
                sizeof(readRequest));
            if (result != rsDone) {
                /*
                 * If pcount == 3, we are supposed to set a new filetype with
                 * the original auxtype.  We really need to be able to read the
                 * original auxtype to do this, so we give an error if we can't.
                 * In other cases, the original AFP info isn't that critical, so
                 * we proceed even if we can't read it (which might be the case
                 * for a write-only file).
                 */
                if (pcount == 3) {
                    if (result != rsFailed
                        || msg.smb2Header.Status != STATUS_END_OF_FILE) {
                        retval = ConvertError(result);
                        goto close_afp_info;
                    }
                }
                infoValid = false;
                goto set_info;
            }
        
            if (readResponse.DataLength != sizeof(AFPInfo)) {
                retval = networkError;
                goto close_afp_info;
            }
        
            if (!VerifyBuffer(readResponse.DataOffset, readResponse.DataLength))
            {
                retval = networkError;
                goto close_afp_info;
            }
    
            infoValid = AFPInfoValid((AFPInfo*)
                ((uint8_t*)&msg.smb2Header + readResponse.DataOffset));
        } else {
            infoValid = false;
        }

set_info:
        /*
         * Set up AFP Info
         */
        if (infoValid) {
            memcpy(&afpInfo,
                (uint8_t*)&msg.smb2Header + readResponse.DataOffset,
                sizeof(AFPInfo));
        } else {
            InitAFPInfo();
        }

        if (pcount != 3) {
            afpInfo.prodosAuxType = fileType.auxType;
        } else {
            originalFileType = GetFileType(gsosdp->path1Ptr, &afpInfo,
                (bool)(attributes & FILE_ATTRIBUTE_DIRECTORY));
            fileType.auxType = originalFileType.auxType;
        }
        afpInfo.prodosType = fileType.fileType;
        
        haveFinderInfo = false;
        if (pcount >= 8) {
            #define pblock ((FileInfoRecGS*)pblock)
            
            if (pblock->optionList != NULL &&
                pblock->optionList->bufSize >= sizeof(FinderInfo) + 6 &&
                pblock->optionList->bufString.length >= sizeof(FinderInfo) + 2)
            {
                fsid = *(Word*)pblock->optionList->bufString.text;
                if (fsid == proDOSFSID || fsid == hfsFSID
                    || fsid == appleShareFSID || fsid == smbFSID) {
                    haveFinderInfo = true;
                    memcpy(&afpInfo.finderInfo,
                        pblock->optionList->bufString.text + 2,
                        sizeof(FinderInfo));
                    }
            }
            
            #undef pblock
        }
        
        if (!haveFinderInfo && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            typeCreator = FileTypeToTypeCreator(fileType, &needSpecificCreator);
            afpInfo.finderInfo.typeCreator.type = typeCreator.type;
            if (needSpecificCreator || !afpInfo.finderInfo.typeCreator.creator)
                afpInfo.finderInfo.typeCreator.creator = typeCreator.creator;
        }

        //TODO Mac always ignores ProDOS type -- maybe don't compare it
        if (!infoValid || memcmp(&afpInfo,
            (uint8_t*)&msg.smb2Header + readResponse.DataOffset,
            sizeof(AFPInfo)) != 0) {
            /*
             * Save AFP Info
             */
            writeRequest.DataOffset =
                sizeof(SMB2Header) + offsetof(SMB2_WRITE_Request, Buffer);
            writeRequest.Length = sizeof(AFPInfo);
            writeRequest.Offset = 0;
            writeRequest.FileId = infoFileID;
            writeRequest.Channel = 0;
            writeRequest.RemainingBytes = 0;
            writeRequest.WriteChannelInfoOffset = 0;
            writeRequest.WriteChannelInfoLength = 0;
            writeRequest.Flags = 0;
            
            memcpy(writeRequest.Buffer, &afpInfo, sizeof(AFPInfo));
    
            result = SendRequestAndGetResponse(dib, SMB2_WRITE,
                sizeof(writeRequest) + sizeof(AFPInfo));
            if (result != rsDone)
                retval = ConvertError(result);
        }

close_afp_info:
        result = SendCloseRequestAndGetResponse(dib, &infoFileID);
        // ignore errors here
    }

finish:
    if (retval == 0 || forcedWritable) {
        /*
         * Set attributes and dates
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
        if (retval == 0) {
            // setting new attributes and dates
            info->CreationTime = createDate;
            info->LastAccessTime = 0;
            info->LastWriteTime = modDate;
            info->ChangeTime = modDate;
            info->FileAttributes = attributes;
            if (info->FileAttributes == 0)
                info->FileAttributes = FILE_ATTRIBUTE_NORMAL;
        } else {
            // trying to restore original attributes in error cases
            info->CreationTime = 0;
            info->LastAccessTime = 0;
            info->LastWriteTime = 0;
            info->ChangeTime = 0;
            info->FileAttributes = originalAttributes;
        }
        info->Reserved = 0;
#undef info
    
        result = SendRequestAndGetResponse(dib, SMB2_SET_INFO,
            sizeof(setInfoRequest) + sizeof(FILE_BASIC_INFORMATION));
        if (result != rsDone)
            retval = retval ? retval : ConvertError(result);
    }

    /*
     * Close file
     */
    result = SendCloseRequestAndGetResponse(dib, &fileID);
    // ignore errors here

    return retval;
}
