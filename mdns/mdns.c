#define USE_BLANK_SEG
#include "defs.h"
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <tcpip.h>
#include <misctool.h>
#include <memory.h>
#include <orca.h>
#include "utils/endian.h"
#include "mdns/mdnsproto.h"
#include "mdns/mdns.h"

static unsigned char nameBuf[DNS_MAX_NAME_LEN], nameBuf2[DNS_MAX_NAME_LEN];

ServerInfo serverInfo;

#define IP_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8

// How often to send out mDNS queries to resolve .local names
#define MDNS_NAME_QUERY_INTERVAL 60 /* ticks */

// Timeout before giving up on mDNS name queries
#define MDNS_NAME_QUERY_TIMEOUT (10 * 60) /* ticks */

// Header for a typical DNS/mDNS query
static DNSHeader queryHeader = {
    .ID = 0,
    .flags1 = DNS_QUERY | DNS_OPCODE_QUERY,
    .flags2 = 0,
    .QDCOUNT = hton16c(1),
    .ANCOUNT = hton16c(0),
    .NSCOUNT = hton16c(0),
    .ARCOUNT = hton16c(0)
};

static unsigned char sdQueryBuf[MDNS_MAX_PACKET_SIZE - IP_HEADER_SIZE - UDP_HEADER_SIZE];
static unsigned char *sdQueryPtr;
static unsigned char *sdQueryNamePtr;
static unsigned char *sdQueryEnd = sdQueryBuf + sizeof(sdQueryBuf);

static ServerHandler *serverHandler;

typedef bool RRFunc(Handle packetHandle, const unsigned char *rrPtr,
    DNSRRFixedPart *rrFields);

static bool ProcessMDNSPacket(Handle packetHandle, RRFunc *rrFunc);

/*
 * Get a name from a DNS packet, and write its fully-expanded form to name.
 *
 * packetHandle contains the DNS packet.
 * dataPtr is the pointer to the beginning of the name in the DNS packet.
 * name is the buffer to write the name to, if any (can be NULL).
 *
 * Returns the position in the DNS packet after the name, or NULL on error.
 */
static const unsigned char *GetName(Handle packetHandle,
    const unsigned char *dataPtr,
    unsigned char name[DNS_MAX_NAME_LEN]) {

    const unsigned char *nameEndPtr = NULL;
    uint16_t len;
    uint16_t nameIndex = 0;
    uint16_t pos;
    uint16_t indirections = 0;
    const unsigned char *startPtr;
    const unsigned char *endPtr;

    startPtr = (void*)*packetHandle;
    endPtr = startPtr + GetHandleSize(packetHandle);

    while (true) {
        if (endPtr - dataPtr < 1)
            return NULL;
        if (nameIndex == DNS_MAX_NAME_LEN)
            return NULL;
        if ((*dataPtr & 0xC0) == 0) {
            // *dataPtr is length
            len = *dataPtr;
            if (name != NULL)
                name[nameIndex++] = len;
            dataPtr++;
            if (endPtr - dataPtr < len)
                return NULL;
            if (nameIndex + len > DNS_MAX_NAME_LEN)
                return NULL;
            if (name != NULL)
                memcpy(name + nameIndex, dataPtr, len);
            nameIndex += len;
            dataPtr += len;
            if (len == 0) {
                // 0-length component terminates
                if (nameEndPtr == NULL)
                    nameEndPtr = dataPtr;
                return nameEndPtr;
            }
        } else if ((*dataPtr & 0xC0) == 0xC0) {
            // compressed name element
            if (endPtr - dataPtr < 2)
                return NULL;
            if (nameEndPtr == NULL)
                nameEndPtr = dataPtr + 2;
            if (name == NULL) {
                // just skipping over the name: we don't need to follow pointer
                return nameEndPtr;
            }
            if (++indirections > DNS_MAX_NAME_LEN)
                return NULL;
            pos = ntoh16(*(uint16_t*)dataPtr) & 0x3fff;
            if (pos >= endPtr - startPtr)
                return NULL;
            dataPtr = startPtr + pos;
        } else {
            return NULL;
        }
    }
}

/*
 * Compare two fully-expanded DNS names for equality.
 */
static bool DNSNamesMatch(const uint8_t *name1, const uint8_t *name2) {
    uint16_t len;
    uint16_t i;

    do {
        len = *name1;
        if (len != *name2)
            return false;
        for (i = 1; i <= len; i++) {
            if (tolower(name1[i]) != tolower(name2[i]))
                return false;
        }
        name1 += len + 1;
        name2 += len + 1;
    } while (len != 0);

    return true;
}

/*
 * Copy the fully-expanded DNS name src to dest, using at most maxLen bytes.
 * Returns pointer to immediately after the copied name, or NULL on error.
 */
static uint8_t *CopyDNSName(uint8_t *dest, const uint8_t *src, uint16_t maxLen)
{
    uint16_t len;

    do {
        len = *src;
        if (len + 1 > maxLen)
            return NULL;
        memcpy(dest, src, len + 1);
        dest += len + 1;
        src += len + 1;
        maxLen -= len + 1;
    } while (len != 0);
    
    return dest;
}

/*
 * Process an A record, mapping a hostname to an IPv4 address.
 */
static bool ProcessA(Handle packetHandle, const unsigned char *rrPtr,
    DNSRRFixedPart *rrFields) {
    DNSARRData *aRRData;

    // Only process RRs with TYPE = A, CLASS = IN, NAME matching nameBuf
    if (ntoh16(rrFields->TYPE) != DNS_TYPE_A)
        return false;
    if ((ntoh16(rrFields->CLASS) & 0x7fff) != DNS_CLASS_IN)
        return false;
    if (GetName(packetHandle, rrPtr, nameBuf2) == NULL)
        return true;
    if (!DNSNamesMatch(nameBuf, nameBuf2))
        return false;

    if (ntoh16(rrFields->RDLENGTH) < sizeof(DNSARRData))
        return true;
    aRRData = (DNSARRData*)rrFields->RDATA;
    
    // Get target address in serverInfo.address
    serverInfo.address = aRRData->ADDRESS;
    serverInfo.hostName = nameBuf;
    
    // Call serverHandler with the full server info
    if (serverHandler)
        serverHandler(&serverInfo);
    
    return false;
}

/*
 * Process a SRV record, mapping a service instance name to a hostname and port.
 */
static bool ProcessSRV(Handle packetHandle, const unsigned char *rrPtr,
    DNSRRFixedPart *rrFields) {
    DNSSRVRRData *srvRRData;

    // Only process RRs with TYPE = SRV, CLASS = IN, NAME matching nameBuf2
    if (ntoh16(rrFields->TYPE) != DNS_TYPE_SRV)
        return false;
    if ((ntoh16(rrFields->CLASS) & 0x7fff) != DNS_CLASS_IN)
        return false;
    if (GetName(packetHandle, rrPtr, nameBuf) == NULL)
        return true;
    if (!DNSNamesMatch(nameBuf, nameBuf2))
        return false;
    
    if (ntoh16(rrFields->RDLENGTH) < sizeof(DNSSRVRRData))
        return true;
    srvRRData = (DNSSRVRRData*)rrFields->RDATA;
    
    // Get target port in serverInfo.port
    serverInfo.port = ntoh16(srvRRData->Port);

    // Get target name in nameBuf
    if (GetName(packetHandle, srvRRData->Target, nameBuf) == NULL)
        return true;

    ProcessMDNSPacket(packetHandle, ProcessA);
    return false;
}

/*
 * Process a PTR record, mapping a service name to a service instance name.
 */
static bool ProcessPTR(Handle packetHandle, const unsigned char *rrPtr,
    DNSRRFixedPart *rrFields) {
    uint8_t *queryRRPtr;
    DNSRRFixedPart *queryRRFields;

    // Only process RRs with TYPE = PTR, CLASS = IN, NAME = queryName
    if (ntoh16(rrFields->TYPE) != DNS_TYPE_PTR)
        return false;
    if ((ntoh16(rrFields->CLASS) & 0x7fff) != DNS_CLASS_IN)
        return false;
    if (GetName(packetHandle, rrPtr, nameBuf) == NULL)
        return true;
    if (!DNSNamesMatch(nameBuf, sdQueryNamePtr))
        return false;

    // Ignore records with TTL of 0, which indicate the resource is going away.
    // TODO Should delete existing copies of this record after 1 second.
    if (rrFields->TTL == 0)
        return false;

    // Get name for SRV record in nameBuf2
    if (GetName(packetHandle, rrFields->RDATA, nameBuf2) == NULL)
        return true;
    
    // Save server name for display
    memcpy(serverInfo.name, nameBuf2, nameBuf2[0] + 1);

    // Copy this PTR record as a "known answer" to suppress future responses
    queryRRPtr = sdQueryPtr;  
    queryRRPtr = CopyDNSName(queryRRPtr, nameBuf, sdQueryEnd-queryRRPtr);
    if (queryRRPtr == NULL)
        goto process;
    if (sdQueryEnd-queryRRPtr < sizeof(DNSRRFixedPart))
        goto process;
    queryRRFields = (DNSRRFixedPart*)queryRRPtr;
    *queryRRFields = *rrFields;
    queryRRPtr += sizeof(DNSRRFixedPart);
    queryRRPtr = CopyDNSName(queryRRPtr, nameBuf2, sdQueryEnd-queryRRPtr);
    if (queryRRPtr == NULL)
        goto process;
    queryRRFields->RDLENGTH = hton16(queryRRPtr - queryRRFields->RDATA);
    /*
     * Set TTL to a big value, which should exceed the record's full TTL.
     * This is needed to suppress responses from Apple's mDNSResponder.
     */
    queryRRFields->TTL = hton32c(0x7FFFFFFF);
    ((DNSHeader*)sdQueryBuf)->ANCOUNT =
        hton16(ntoh16(((DNSHeader*)sdQueryBuf)->ANCOUNT) + 1);
    sdQueryPtr = queryRRPtr;

process:
    ProcessMDNSPacket(packetHandle, ProcessSRV);
    return false;
}

/*
 * Process an mDNS packet, calling rrFunc on each response record in it
 * (unless a call returns true, indicating the processing should stop).
 */
static bool ProcessMDNSPacket(Handle packetHandle, RRFunc *rrFunc) {
    const unsigned char *dataPtr;
    const unsigned char *endPtr;
    const unsigned char *rrPtr;
    DNSHeader *header;
    uint16_t qCount;
    uint32_t rrCount;
    DNSRRFixedPart *rr;
    uint16_t rdLength;
    uint16_t i;

    dataPtr = (void*)*packetHandle;
    endPtr = dataPtr + GetHandleSize(packetHandle);
    
    if (endPtr - dataPtr < sizeof(DNSHeader))
        return false;
    header = (DNSHeader*)dataPtr;

    if ((header->flags1 & (DNS_QR | DNS_AA)) != (DNS_QR | DNS_AA))
        return false;
    
    if ((header->flags2 & DNS_RCODE_MASK) != 0)
        return false;
    
    qCount = ntoh16(header->QDCOUNT);
    rrCount = (uint32_t)ntoh16(header->ANCOUNT)
        + ntoh16(header->NSCOUNT)
        + ntoh16(header->ARCOUNT);
    if (rrCount > UINT16_MAX)
        return false;
    
    dataPtr += sizeof(DNSHeader);
    
    for (i = 0; i < qCount; i++) {
        dataPtr = GetName(packetHandle, dataPtr, NULL);
        if (dataPtr == NULL)
            return false;
        if (endPtr - dataPtr < sizeof(DNSQuestionFixedPart))
            return false;
        dataPtr += sizeof(DNSQuestionFixedPart);
    }
    
    for (i = 0; i < rrCount; i++) {
        rrPtr = dataPtr;
        dataPtr = GetName(packetHandle, dataPtr, nameBuf);
        if (dataPtr == NULL)
            return false;
        if (endPtr - dataPtr < sizeof(DNSRRFixedPart))
            return false;
        rr = (DNSRRFixedPart *)dataPtr;
        dataPtr += sizeof(DNSRRFixedPart);
        rdLength = ntoh16(rr->RDLENGTH);
        if (endPtr - dataPtr < rdLength)
            return false;
        dataPtr += rdLength;
        
        if (rrFunc(packetHandle, nameBuf, rr))
            return true;
    }

    return true;
}

/*
 * Process an mDNS-SD packet, calling handler with the full server information
 * that can be derived from the packet, if any.  (The handler may be called
 * multiple times with info for multiple servers, although this is unusual.)
 */
void MDNSSDProcessPacket(Handle packetHandle, ServerHandler *handler) {
    serverHandler = handler;
    HLock(packetHandle);
    ProcessMDNSPacket(packetHandle, ProcessPTR);
}

/*
 * Initialize mDNS-SD state to query for the specified name.
 */
void MDNSSDInitQuery(const uint8_t *queryName) {
    sdQueryPtr = sdQueryBuf;

    memcpy(sdQueryPtr, &queryHeader, sizeof(queryHeader));
    sdQueryPtr += sizeof(queryHeader);
    
    sdQueryNamePtr = sdQueryPtr;
    sdQueryPtr = CopyDNSName(sdQueryPtr, queryName, DNS_MAX_NAME_LEN);
    
    *(uint16_t*)sdQueryPtr = hton16c(DNS_TYPE_PTR);
    sdQueryPtr += sizeof(uint16_t);
    
    *(uint16_t*)sdQueryPtr = hton16c(DNS_CLASS_IN | MDNS_FLAG_QU);
    sdQueryPtr += sizeof(uint16_t);
}

/*
 * Send out an mDNS-SD query.
 */
void MDNSSDSendQuery(Word ipid) {
    TCPIPSendUDP(ipid, (Pointer)sdQueryBuf, sdQueryPtr - sdQueryBuf);
}

/*
 * Send out an mDNS query.
 */
void MDNSSendQuery(Word ipid, void *query, size_t len) {
    TCPIPSendUDP(ipid, query, len);
}

/*
 * Encode a domain name in the form used by DNS packets.
 *
 * Returns a pointer to immediately after the encoded name on success,
 * or NULL on failure.
 */
static unsigned char * DNSEncodeName(unsigned char *buf, const char *name) {
    size_t componentLen;
    unsigned remainingLen;
    char *dotPtr;

    remainingLen = DNS_MAX_NAME_LEN;

    do {
        dotPtr = strchr(name, '.');
        if (dotPtr) {
            componentLen = dotPtr - name;
            if (componentLen == 0 && name[1] != '\0')
                return NULL;
        } else {
            componentLen = strlen(name);
        }
    
        if (componentLen >= remainingLen || componentLen > DNS_MAX_LABEL_LEN)
            return NULL;
    
        *buf++ = componentLen;
        memcpy(buf, name, componentLen);
        buf += componentLen;
        
        remainingLen -= componentLen;
        if (dotPtr) {
            name = dotPtr + 1;
        } else {
            name += componentLen;
        }
    } while (componentLen != 0);

    return buf;
}

/*
 * Resolve a name to an IP address via mDNS.  Returns the IP address on
 * success, or 0 on failure.
 *
 * This is normally used for .local addresses.
 */
Long MDNSResolveName(char *name) {
    size_t len;
    unsigned char *query = NULL;
    Word ipid;
    DNSQuestionFixedPart *questionFixedPart;
    Handle dgmHandle;
    Long startTime, lastTime;
    
    len = strlen(name);
    if (len != 0 && name[len-1] == '.')
        len--;

    len += sizeof(DNSHeader) + sizeof(DNSQuestionFixedPart) + 2;

    query = malloc(len);
    if (!query)
        return 0;

    *(DNSHeader *)query = queryHeader;
    questionFixedPart = (DNSQuestionFixedPart *)
        DNSEncodeName(query + sizeof(queryHeader), name);
    if (questionFixedPart == NULL)
        goto finish;
    questionFixedPart->QTYPE = hton16c(DNS_TYPE_A);
    questionFixedPart->QCLASS = hton16c(DNS_CLASS_IN | MDNS_FLAG_QU);

    ipid = TCPIPLogin(userid(), MDNS_IP, MDNS_PORT, 0, 0x40);
    if (toolerror())
        goto finish;

    // Don't send from the mDNS port, which indicates a full mDNS implementation
    if (TCPIPGetSourcePort(ipid) == MDNS_PORT)
        TCPIPSetSourcePort(ipid, 59628);

    serverInfo.address = 0;
    startTime = GetTick();
    lastTime = 0;
    do {
        if (GetTick() - lastTime > MDNS_NAME_QUERY_INTERVAL) {
            MDNSSendQuery(ipid, query, len);
            lastTime = GetTick();
        }
        TCPIPPoll();
        dgmHandle = TCPIPGetNextDatagram(ipid, protocolUDP, 0xC000);
        if (toolerror())
            break;
        if (dgmHandle != NULL) {
            serverHandler = NULL;
            HLock(dgmHandle);
            ProcessMDNSPacket(dgmHandle, ProcessA);
            DisposeHandle(dgmHandle);
        }
    } while (serverInfo.address == 0
        && GetTick() - startTime < MDNS_NAME_QUERY_TIMEOUT);

    TCPIPLogout(ipid);

finish:
    free(query);
    return serverInfo.address;
}
