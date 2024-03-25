/*
 * File information data structures.
 *
 * See [MS-FSCC].
 */

#include <stdint.h>
#include <uchar.h>

/* FileInformationClass values */
// File information (from [MS-FSCC] section 2.4)
#define FileAccessInformation              8
#define FileAlignmentInformation           17
#define FileAllInformation                 18
#define FileAllocationInformation          19
#define FileAlternateNameInformation       21
#define FileAttributeTagInformation        35
#define FileBasicInformation               4
#define FileBothDirectoryInformation       3
#define FileCompressionInformation         28
#define FileDirectoryInformation           1
#define FileDispositionInformation         13
#define FileEaInformation                  7
#define FileEndOfFileInformation           20
#define FileFullDirectoryInformation       2
#define FileFullEaInformation              15
#define FileHardLinkInformation            46
#define FileIdBothDirectoryInformation     37
#define FileIdExtdDirectoryInformation     60
#define FileIdFullDirectoryInformation     38
#define FileIdGlobalTxDirectoryInformation 50
#define FileIdInformation                  59
#define FileInternalInformation            6
#define FileLinkInformation                11
#define FileMailslotQueryInformation       26
#define FileMailslotSetInformation         27
#define FileModeInformation                16
#define FileMoveClusterInformation         31
#define FileNameInformation                9
#define FileNamesInformation               12
#define FileNetworkOpenInformation         34
#define FileNormalizedNameInformation      48
#define FileObjectIdInformation            29
#define FilePipeInformation                23
#define FilePipeLocalInformation           24
#define FilePipeRemoteInformation          25
#define FilePositionInformation            14
#define FileQuotaInformation               32
#define FileRenameInformation              10
#define FileReparsePointInformation        33
#define FileSfioReserveInformation         44
#define FileSfioVolumeInformation          45
#define FileShortNameInformation           40
#define FileStandardInformation            5
#define FileStandardLinkInformation        54
#define FileStreamInformation              22
#define FileTrackingInformation            36
#define FileValidDataLengthInformation     39
// File system information (from [MS-FSCC] section 2.5)
#define FileFsVolumeInformation            1
#define FileFsLabelInformation             2
#define FileFsSizeInformation              3
#define FileFsDeviceInformation            4
#define FileFsAttributeInformation         5
#define FileFsControlInformation           6
#define FileFsFullSizeInformation          7
#define FileFsObjectIdInformation          8
#define FileFsDriverPathInformation        9
#define FileFsVolumeFlagsInformation       10
#define FileFsSectorSizeInformation        11
// Reserved value
#define FileInfoClass_Reserved             0x64

/* File attributes (from [MS-FSCC] section 2.6) */
#define FILE_ATTRIBUTE_READONLY              0x00000001
#define FILE_ATTRIBUTE_HIDDEN                0x00000002
#define FILE_ATTRIBUTE_SYSTEM                0x00000004
#define FILE_ATTRIBUTE_DIRECTORY             0x00000010
#define FILE_ATTRIBUTE_ARCHIVE               0x00000020
#define FILE_ATTRIBUTE_NORMAL                0x00000080
#define FILE_ATTRIBUTE_TEMPORARY             0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE           0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT         0x00000400
#define FILE_ATTRIBUTE_COMPRESSED            0x00000800
#define FILE_ATTRIBUTE_OFFLINE               0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED   0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED             0x00004000
#define FILE_ATTRIBUTE_INTEGRITY_STREAM      0x00008000
#define FILE_ATTRIBUTE_NO_SCRUB_DATA         0x00020000
#define FILE_ATTRIBUTE_RECALL_ON_OPEN        0x00040000
#define FILE_ATTRIBUTE_PINNED                0x00080000
#define FILE_ATTRIBUTE_UNPINNED              0x00100000
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS 0x00400000

typedef struct {
    uint32_t NextEntryOffset;
    uint32_t FileIndex;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t EndOfFile;
    uint64_t AllocationSize;
    uint32_t FileAttributes;
    uint32_t FileNameLength;
    uint16_t FileName[];
} FILE_DIRECTORY_INFORMATION;

typedef struct {
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint32_t FileAttributes;
    uint32_t Reserved;
} FILE_BASIC_INFORMATION;

typedef struct {
    uint64_t ReplaceIfExists; /* and reserved space */
    uint64_t RootDirectory;
    uint32_t FileNameLength;
    char16_t FileName[]; /* and possible padding if needed to reach min size */
} FILE_RENAME_INFORMATION_TYPE_2;

#define FILE_RENAME_INFORMATION_TYPE_2_MIN_SIZE 24

typedef struct {
    uint8_t  DeletePending;
} FILE_DISPOSITION_INFORMATION;
