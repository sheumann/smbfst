#ifndef __SMB2PROTO_H__
#define __SMB2PROTO_H__

#include <stdint.h>

#include "ntstatus.h"

#define SMB2_ASSERT_SIZE(type,size) _Static_assert(sizeof(type) == (size), "");

#define SMB_PORT 445

typedef struct {
    uint64_t hi;
    uint64_t lo;
} smb_u128;

/* Direct TCP transport header */
typedef struct {
    uint32_t StreamProtocolLength; /* big-endian; high-order byte must be 0 */
} DirectTCPHeader;

/* SMB2 message header (sync/async) */
typedef struct {
    /* SMB2 header */
    uint32_t ProtocolId;
    uint16_t StructureSize;
    uint16_t CreditCharge;
    union {
        struct {
            uint16_t ChannelSequence;
            uint16_t Reserved;
        };
        uint32_t Status;
    };
    uint16_t Command;
    union {
        uint16_t CreditRequest;
        uint16_t CreditResponse;
    };
    uint32_t Flags;
    uint32_t NextCommand;
    uint64_t MessageId;
    union {
        struct {
            uint32_t Reserved2;
            uint32_t TreeId;
        };
        uint64_t AsyncId;
    };
    uint64_t SessionId;
    smb_u128 Signature;
} SMB2Header;
SMB2_ASSERT_SIZE(SMB2Header,64)

/* SMB2 commands */
#define SMB2_NEGOTIATE       0x0000
#define SMB2_SESSION_SETUP   0x0001
#define SMB2_LOGOFF          0x0002
#define SMB2_TREE_CONNECT    0x0003
#define SMB2_TREE_DISCONNECT 0x0004
#define SMB2_CREATE          0x0005
#define SMB2_CLOSE           0x0006
#define SMB2_FLUSH           0x0007
#define SMB2_READ            0x0008
#define SMB2_WRITE           0x0009
#define SMB2_LOCK            0x000A
#define SMB2_IOCTL           0x000B
#define SMB2_CANCEL          0x000C
#define SMB2_ECHO            0x000D
#define SMB2_QUERY_DIRECTORY 0x000E
#define SMB2_CHANGE_NOTIFY   0x000F
#define SMB2_QUERY_INFO      0x0010
#define SMB2_SET_INFO        0x0011
#define SMB2_OPLOCK_BREAK    0x0012
#define SMB2 SERVER_TO_CLIENT_NOTIFICATION 0x0013

/* SMB2 message flags */
#define SMB2_FLAGS_SERVER_TO_REDIR    0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND      0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS 0x00000004
#define SMB2_FLAGS_SIGNED             0x00000008
#define SMB2_FLAGS_PRIORITY_MASK      0x00000070
#define SMB2_FLAGS_DFS_OPERATIONS     0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION   0x20000000

/* Common header field for the body part of all SMB2 messages */
typedef struct {
    uint16_t StructureSize;
} SMB2_Common_Header;

/* Individual message structures */

typedef struct {
    uint16_t StructureSize;
    uint16_t DialectCount;
    uint16_t SecurityMode;
    uint16_t Reserved;
    uint32_t Capabilities;
    smb_u128 ClientGuid;
    union {
        struct {
            uint32_t NegotiateContextOffset;
            uint16_t NegotiateContextCount;
            uint16_t Reserved2;
        };
        uint64_t ClientStartTime;
    };
    uint16_t Dialects[];
} SMB2_NEGOTIATE_Request;
SMB2_ASSERT_SIZE(SMB2_NEGOTIATE_Request,36)

/* SMB protocol dialects */
#define SMB_202 0x0202
#define SMB_21  0x0210
#define SMB_30  0x0300
#define SMB_302 0x0302
#define SMB_311 0x0311

typedef struct {
    uint16_t StructureSize;
    uint16_t SecurityMode;
    uint16_t DialectRevision;
    union {
        uint16_t NegotiateContextCount;
        uint16_t Reserved;
    };
    smb_u128 ServerGuid;
    uint32_t Capabilities;
    uint32_t MaxTransactSize;
    uint32_t MaxReadSize;
    uint32_t MaxWriteSize;
    uint64_t SystemTime;
    uint64_t ServerStartTime;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    union {
        uint32_t NegotiateContextOffset;
        uint32_t Reserved2;
    };
    uint8_t  Buffer[];
} SMB2_NEGOTIATE_Response;
SMB2_ASSERT_SIZE(SMB2_NEGOTIATE_Response,64)

/* SecurityMode flags */
#define SMB2_NEGOTIATE_SIGNING_ENABLED  0x0001
#define SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002

/* Capabilities flags */
#define SMB2_GLOBAL_CAP_DFS                0x00000001
#define SMB2_GLOBAL_CAP_LEASING            0x00000002
#define SMB2_GLOBAL_CAP_LARGE_MTU          0x00000004
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL      0x00000008
#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010
#define SMB2_GLOBAL_CAP_DIRECTORY_LEASING  0x00000020
#define SMB2_GLOBAL_CAP_ENCRYPTION         0x00000040

typedef struct {
    uint16_t StructureSize;
    uint8_t  Flags;
    uint8_t  SecurityMode;
    uint32_t Capabilities;
    uint32_t Channel;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    uint64_t PreviousSessionId;
    uint8_t  Buffer[];
} SMB2_SESSION_SETUP_Request;
SMB2_ASSERT_SIZE(SMB2_SESSION_SETUP_Request,24)

typedef struct {
    uint16_t StructureSize;
    uint16_t SessionFlags;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    uint8_t  Buffer[];
} SMB2_SESSION_SETUP_Response;

/* SessionFlags flags */
#define SMB2_SESSION_FLAG_IS_GUEST     0x0001
#define SMB2_SESSION_FLAG_IS_NULL      0x0002
#define SMB2_SESSION_FLAG_ENCRYPT_DATA 0x0004

typedef struct {
    uint16_t StructureSize;
    union {
        uint16_t Flags;
        uint16_t Reserved;
    };
    uint16_t PathOffset;
    uint16_t PathLength;
    uint8_t Buffer[];
} SMB2_TREE_CONNECT_Request;

/* Tree Connect request flags */
#define SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT 0x0001
#define SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER 0x0002
#define SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT 0x0004

typedef struct {
    uint16_t StructureSize;
    uint8_t  ShareType;
    uint8_t  Reserved;
    uint32_t ShareFlags;
    uint32_t Capabilities;
    uint32_t MaximalAccess;
} SMB2_TREE_CONNECT_Response;

/* ShareType values */
#define SMB2_SHARE_TYPE_DISK  0x01
#define SMB2_SHARE_TYPE_PIPE  0x02
#define SMB2_SHARE_TYPE_PRINT 0x03

/* ShareFlags flags */
#define SMB2_SHAREFLAG_MANUAL_CACHING              0x00000000
#define SMB2_SHAREFLAG_AUTO_CACHING                0x00000010
#define SMB2_SHAREFLAG_VDO_CACHING                 0x00000020
#define SMB2_SHAREFLAG_NO_CACHING                  0x00000030
#define SMB2_SHAREFLAG_DFS                         0x00000001
#define SMB2_SHAREFLAG_DFS_ROOT                    0x00000002
#define SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS    0x00000100
#define SMB2_SHAREFLAG_FORCE_SHARED_DELETE         0x00000200
#define SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING     0x00000400
#define SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM 0x00000800
#define SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK        0x00001000
#define SMB2_SHAREFLAG_ENABLE_HASH_V1              0x00002000
#define SMB2_SHAREFLAG_ENABLE_HASH_V2              0x00004000
#define SMB2_SHAREFLAG_ENCRYPT_DATA                0x00008000
#define SMB2_SHAREFLAG_IDENTITY_REMOTING           0x00040000
#define SMB2_SHAREFLAG_COMPRESS_DATA               0x00100000
#define SMB2_SHAREFLAG_ISOLATED_TRANSPORT          0x00200000

/* Capabilities flags */
#define SMB2_SHARE_CAP_DFS                     0x00000008
#define SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY 0x00000010
#define SMB2_SHARE_CAP_SCALEOUT                0x00000020
#define SMB2_SHARE_CAP_CLUSTER                 0x00000040
#define SMB2_SHARE_CAP_ASYMMETRIC              0x00000080
#define SMB2_SHARE_CAP_REDIRECT_TO_OWNER       0x00000100

typedef struct {
    uint16_t StructureSize;
    uint8_t  SecurityFlags;
    uint8_t  RequestedOplockLevel;
    uint32_t ImpersonationLevel;
    uint64_t SmbCreateFlags;
    uint64_t Reserved;
    uint32_t DesiredAccess;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    uint32_t CreateDisposition;
    uint32_t CreateOptions;
    uint16_t NameOffset;
    uint16_t NameLength;
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
    uint8_t  Buffer[];
} SMB2_CREATE_Request;

/* RequestedOplockLevel values */
#define SMB2_OPLOCK_LEVEL_NONE      0x00
#define SMB2_OPLOCK_LEVEL_II        0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE 0x08
#define SMB2_OPLOCK_LEVEL_BATCH     0x09
#define SMB2_OPLOCK_LEVEL_LEASE     0xFF

/* Impersonation values */
#define Anonymous      0x00000000
#define Identification 0x00000001
#define Impersonation  0x00000002
#define Delegate       0x00000003

/* ShareAccess flags */
#define FILE_SHARE_READ   0x00000001
#define FILE_SHARE_WRITE  0x00000002
#define FILE_SHARE_DELETE 0x00000004

/* CreateDisposition values */
#define FILE_SUPERSEDE    0x00000000
#define FILE_OPEN         0x00000001
#define FILE_CREATE       0x00000002
#define FILE_OPEN_IF      0x00000003
#define FILE_OVERWRITE    0x00000004
#define FILE_OVERWRITE_IF 0x00000005

/* CreateOptions flags */
#define FILE_DIRECTORY_FILE            0x00000001
#define FILE_WRITE_THROUGH             0x00000002
#define FILE_SEQUENTIAL_ONLY           0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT      0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT   0x00000020
#define FILE_NON_DIRECTORY_FILE        0x00000040
#define FILE_COMPLETE_IF_OPLOCKED      0x00000100
#define FILE_NO_EA_KNOWLEDGE           0x00000200
#define FILE_RANDOM_ACCESS             0x00000800
#define FILE_DELETE_ON_CLOSE           0x00001000
#define FILE_OPEN_BY_FILE_ID           0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT    0x00004000
#define FILE_NO_COMPRESSION            0x00008000
#define FILE_OPEN_REMOTE_INSTANCE      0x00000400
#define FILE_OPEN_REQUIRING_OPLOCK     0x00010000
#define FILE_DISALLOW_EXCLUSIVE        0x00020000
#define FILE_RESERVE_OPFILTER          0x00100000
#define FILE_OPEN_REPARSE_POINT        0x00200000
#define FILE_OPEN_NO_RECALL            0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000

/* file/pipe/printer access mask flags */
#define FILE_READ_DATA         0x00000001
#define FILE_WRITE_DATA        0x00000002
#define FILE_APPEND_DATA       0x00000004
#define FILE_READ_EA           0x00000008
#define FILE_WRITE_EA          0x00000010
#define FILE_DELETE_CHILD      0x00000040
#define FILE_EXECUTE           0x00000020
#define FILE_READ_ATTRIBUTES   0x00000080
#define FILE_WRITE_ATTRIBUTES  0x00000100
#define DELETE                 0x00010000
#define READ_CONTROL           0x00020000
#define WRITE_DAC              0x00040000
#define WRITE_OWNER            0x00080000
#define SYNCHRONIZE            0x00100000
#define ACCESS_SYSTEM_SECURITY 0x01000000
#define MAXIMUM_ALLOWED        0x02000000
#define GENERIC_ALL            0x10000000
#define GENERIC_EXECUTE        0x20000000
#define GENERIC_WRITE          0x40000000
#define GENERIC_READ           0x80000000

/* directory access mask flags */
#define FILE_LIST_DIRECTORY    0x00000001
#define FILE_ADD_FILE          0x00000002
#define FILE_ADD_SUBDIRECTORY  0x00000004
#define FILE_READ_EA           0x00000008
#define FILE_WRITE_EA          0x00000010
#define FILE_TRAVERSE          0x00000020
#define FILE_DELETE_CHILD      0x00000040
#define FILE_READ_ATTRIBUTES   0x00000080
#define FILE_WRITE_ATTRIBUTES  0x00000100
#define DELETE                 0x00010000
#define READ_CONTROL           0x00020000
#define WRITE_DAC              0x00040000
#define WRITE_OWNER            0x00080000
#define SYNCHRONIZE            0x00100000
#define ACCESS_SYSTEM_SECURITY 0x01000000
#define MAXIMUM_ALLOWED        0x02000000
#define GENERIC_ALL            0x10000000
#define GENERIC_EXECUTE        0x20000000
#define GENERIC_WRITE          0x40000000
#define GENERIC_READ           0x80000000

typedef struct {
    uint64_t Persistent;
    uint64_t Volatile;
} SMB2_FILEID;

typedef struct {
    uint16_t StructureSize;
    uint8_t  OplockLevel;
    uint8_t  Flags;
    uint32_t CreateAction;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndofFile;
    uint32_t FileAttributes;
    uint32_t Reserved2;
    SMB2_FILEID FileId;
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
    uint8_t  Buffer[];
} SMB2_CREATE_Response;

typedef struct {
    uint16_t StructureSize;
    uint8_t  Padding;
    uint8_t  Flags;
    uint32_t Length;
    uint64_t Offset;
    SMB2_FILEID FileId;
    uint32_t MinimumCount;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t ReadChannelInfoOffset;
    uint16_t ReadChannelInfoLength;
    uint8_t  Buffer[];
} SMB2_READ_Request;

/* Read request flags (SMB 3.0.2+) */
#define SMB2_READFLAG_READ_UNBUFFERED    0x01
#define SMB2_READFLAG_REQUEST_COMPRESSED 0x02

/* Channel values (SMB 3.0+) */
#define SMB2_CHANNEL_NONE               0x00000000
#define SMB2_CHANNEL_RDMA_V1            0x00000001
#define SMB2_CHANNEL_RDMA_V1_INVALIDATE 0x00000002
#define SMB2_CHANNEL_RDMA_TRANSFORM     0x00000003

typedef struct {
    uint16_t StructureSize;
    uint8_t  DataOffset;
    uint8_t  Reserved;
    uint32_t DataLength;
    uint32_t DataRemaining;
    union {
        uint32_t Reserved2;
        uint32_t Flags;
    };
    uint8_t  Buffer[];
} SMB2_READ_Response;

typedef struct {
    uint16_t StructureSize;
    uint16_t Flags;
    uint32_t Reserved;
    SMB2_FILEID FileId;
} SMB2_CLOSE_Request;

/* Close request flags */
#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB 0x0001

typedef struct {
    uint16_t StructureSize;
    uint8_t  FileInformationClass;
    uint8_t  Flags;
    uint32_t FileIndex;
    SMB2_FILEID FileId;
    uint16_t FileNameOffset;
    uint16_t FileNameLength;
    uint32_t OutputBufferLength;
    uint8_t  Buffer[];
} SMB2_QUERY_DIRECTORY_Request;

/* Query Directory request flags */
#define SMB2_RESTART_SCANS       0x01
#define SMB2_RETURN_SINGLE_ENTRY 0x02
#define SMB2_INDEX_SPECIFIED     0x04
#define SMB2_REOPEN              0x10

typedef struct {
    uint16_t StructureSize;
    uint16_t OutputBufferOffset;
    uint16_t OutputBufferLength;
    uint8_t  Buffer[];
} SMB2_QUERY_DIRECTORY_Response;

typedef struct {
    uint16_t StructureSize;
    uint8_t  InfoType;
    uint8_t  FileInfoClass;
    uint32_t OutputBufferLength;
    uint16_t InputBufferOffset;
    uint16_t Reserved;
    uint32_t InputBufferLength;
    uint32_t AdditionalInformation;
    uint32_t Flags;
    SMB2_FILEID FileId;
    uint8_t  Buffer[];
} SMB2_QUERY_INFO_Request;

/* InfoType values */
#define SMB2_0_INFO_FILE       0x01
#define SMB2_0_INFO_FILESYSTEM 0x02
#define SMB2_0_INFO_SECURITY   0x03
#define SMB2_0_INFO_QUOTA      0x04

typedef struct {
    uint16_t StructureSize;
    uint16_t OutputBufferOffset;
    uint32_t OutputBufferLength;
    uint8_t  Buffer[];
} SMB2_QUERY_INFO_Response;


typedef struct {
    uint16_t StructureSize;
    uint8_t  InfoType;
    uint8_t  FileInfoClass;
    uint32_t BufferLength;
    uint16_t BufferOffset;
    uint16_t Reserved;
    uint32_t AdditionalInformation;
    SMB2_FILEID FileId;
    uint8_t  Buffer[];
} SMB2_SET_INFO_Request;

typedef struct {
    uint16_t StructureSize;
} SMB2_SET_INFO_Response;

typedef struct {
    uint16_t StructureSize;
    uint16_t Reserved1;
    uint32_t Reserved2;
    SMB2_FILEID FileId;
} SMB2_FLUSH_Request;

typedef struct {
    uint16_t StructureSize;
    uint16_t Reserved;
} SMB2_FLUSH_Response;

typedef struct {
    uint16_t StructureSize;
    uint16_t DataOffset;
    uint32_t Length;
    uint64_t Offset;
    SMB2_FILEID FileId;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
    uint32_t Flags;
    uint8_t  Buffer[];
} SMB2_WRITE_Request;

/* Write request flags */
#define SMB2_WRITEFLAG_WRITE_THROUGH    0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED 0x00000002

typedef struct {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t Count;
    uint32_t Remaining;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
} SMB2_WRITE_Response;

#endif
