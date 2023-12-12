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
