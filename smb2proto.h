#include <stdint.h>

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
_Static_assert(sizeof(SMB2Header) == 64, "");

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

/* SMB2 message flags */
#define SMB2_FLAGS_SERVER_TO_REDIR    0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND      0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS 0x00000004
#define SMB2_FLAGS_SIGNED             0x00000008
#define SMB2_FLAGS_PRIORITY_MASK      0x00000070
#define SMB2_FLAGS_DFS_OPERATIONS     0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION   0x20000000

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
_Static_assert(sizeof(SMB2_NEGOTIATE_Request) == 36, "");

/* SMB protocol dialects */
#define SMB_202 0x0202
#define SMB_21  0x0210
#define SMB_30  0x0300
#define SMB_302 0x0302
#define SMB_311 0x0311
