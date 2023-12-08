#include <stdint.h>

#define NTLM_ASSERT_SIZE(type,size) _Static_assert(sizeof(type) == (size), "");

typedef struct {
    uint8_t  ProductMajorVersion;
    uint8_t  ProductMinorVersion;
    uint16_t ProductBuild;
    uint8_t  Reserved[3];
    uint8_t  NTLMRevisionCurrent;
} NTLM_VERSION;
NTLM_ASSERT_SIZE(NTLM_VERSION,8)

/* revision value */
#define NTLMSSP_REVISION_W2K3 0x0F

typedef struct {
    uint16_t Len;
    uint16_t MaxLen;
    uint32_t BufferOffset;
} NTLM_SUBFIELD;
NTLM_ASSERT_SIZE(NTLM_SUBFIELD,8)

typedef struct {
    uint8_t  Signature[8];
    uint32_t MessageType;
    uint32_t NegotiateFlags;
    NTLM_SUBFIELD DomainNameFields;
    NTLM_SUBFIELD WorkstationFields;
    NTLM_VERSION Version;
    uint8_t  Payload[];
} NTLM_NEGOTIATE_MESSAGE;
NTLM_ASSERT_SIZE(NTLM_NEGOTIATE_MESSAGE,40)

typedef struct {
    uint8_t  Signature[8];
    uint32_t MessageType;
    NTLM_SUBFIELD TargetNameFields;
    uint32_t NegotiateFlags;
    uint64_t ServerChallenge;
    uint64_t Reserved;
    NTLM_SUBFIELD TargetInfoFields;
    NTLM_VERSION Version;
    uint8_t  Payload[];
} NTLM_CHALLENGE_MESSAGE;
NTLM_ASSERT_SIZE(NTLM_CHALLENGE_MESSAGE,56)

typedef struct {
    uint8_t  Signature[8];
    uint32_t MessageType;
    NTLM_SUBFIELD LmChallengeResponseFields;
    NTLM_SUBFIELD NtChallengeResponseFields;
    NTLM_SUBFIELD DomainNameFields;
    NTLM_SUBFIELD UserNameFields;
    NTLM_SUBFIELD WorkstationNameFields;
    NTLM_SUBFIELD EncryptedRandomSessionKeyFields;
    uint32_t NegotiateFlags;
    NTLM_VERSION Version;
    uint8_t  MIC[16];
    uint8_t  Payload[];
} NTLM_AUTHENTICATE_MESSAGE;
NTLM_ASSERT_SIZE(NTLM_AUTHENTICATE_MESSAGE,88)

typedef struct {
    uint8_t  Response[16];
    uint8_t  ChallengeFromClient[8];
} LMv2_RESPONSE;
NTLM_ASSERT_SIZE(LMv2_RESPONSE,24)

typedef struct {
    uint8_t  Response[16];
    uint8_t  NTLMv2_CLIENT_CHALLENGE[];
} NTLMv2_RESPONSE;
NTLM_ASSERT_SIZE(NTLMv2_RESPONSE,16)

/* negotiate flags */
#define NTLMSSP_NEGOTIATE_56                       0x80000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH                 0x40000000
#define NTLMSSP_NEGOTIATE_128                      0x20000000
#define NTLMSSP_NEGOTIATE_VERSION                  0x02000000
#define NTLMSSP_NEGOTIATE_TARGET_INFO              0x00800000
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY         0x00400000
#define NTLMSSP_NEGOTIATE_IDENTIFY                 0x00100000
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY 0x00080000
#define NTLMSSP_TARGET_TYPE_SERVER                 0x00020000
#define NTLMSSP_TARGET_TYPE_DOMAIN                 0x00010000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN              0x00008000
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED 0x00002000
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      0x00001000
#define NTLMSSP_ANONYMOUS                          0x00000800
#define NTLMSSP_NEGOTIATE_NTLM                     0x00000200
#define NTLMSSP_NEGOTIATE_LM_KEY                   0x00000080
#define NTLMSSP_NEGOTIATE_DATAGRAM                 0x00000040
#define NTLMSSP_NEGOTIATE_SEAL                     0x00000020
#define NTLMSSP_NEGOTIATE_SIGN                     0x00000010
#define NTLMSSP_REQUEST_TARGET                     0x00000004
#define NTLM_NEGOTIATE_OEM                         0x00000002
#define NTLMSSP_NEGOTIATE_UNICODE                  0x00000001

/* MessageType values */
#define NtLmNegotiate    1
#define NtLmChallenge    2
#define NtLmAuthenticate 3

typedef struct {
    uint8_t  RespType;
    uint8_t  HiRespType;
    uint16_t Reserved1;
    uint32_t Reserved2;
    uint64_t TimeStamp;
    uint64_t ChallengeFromClient;
    uint32_t Reserved3;
    uint8_t  AvPairs[];
} NTLMv2_CLIENT_CHALLENGE;

typedef struct {
    uint16_t AvId;
    uint16_t AvLen;
    uint8_t  Value[];
} AV_PAIR;

/* AvId values */
#define MsvAvEOL             0x0000
#define MsvAvNbComputerName  0x0001
#define MsvAvNbDomainName    0x0002
#define MsvAvDnsComputerName 0x0003
#define MsvAvDnsDomainName   0x0004
#define MsvAvDnsTreeName     0x0005
#define MsvAvFlags           0x0006
#define MsvAvTimestamp       0x0007
#define MsvAvSingleHost      0x0008
#define MsvAvTargetName      0x0009
#define MsvAvChannelBindings 0x000A
