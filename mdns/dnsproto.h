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

#ifndef DNSPROTO_H
#define DNSPROTO_H

#include <stdint.h>

/* DNS data structures (see RFC 1035) */

typedef struct {
    uint16_t ID;
    uint8_t  flags1;
    uint8_t  flags2;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
} DNSHeader;

typedef struct {
    uint16_t QTYPE;
    uint16_t QCLASS;
} DNSQuestionFixedPart;

typedef struct {
    uint16_t TYPE;
    uint16_t CLASS;
    uint32_t TTL;
    uint16_t RDLENGTH;
    uint8_t  RDATA[];
} DNSRRFixedPart;

/* values within flags1 */
#define DNS_QUERY    (0 << 7)
#define DNS_RESPONSE (1 << 7)

#define DNS_OPCODE_QUERY  (0 << 3)
#define DNS_OPCODE_IQUERY (1 << 3)
#define DNS_OPCODE_STATUS (2 << 3)

#define DNS_QR 0x80
#define DNS_AA 0x04
#define DNS_TC 0x02
#define DNS_RD 0x01

/* values within flags2 */
#define DNS_RA 0x80
#define DNS_AD 0x20 /* DNSSEC */
#define DNS_CD 0x10 /* DNSSEC */

#define DNS_RCODE_MASK 0x0F

/* TYPE values used in Resource Records and queries */
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_MD     3
#define DNS_TYPE_MF     4
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_MB     7
#define DNS_TYPE_MG     8
#define DNS_TYPE_MR     9
#define DNS_TYPE_NULL   10
#define DNS_TYPE_WKS    11
#define DNS_TYPE_PTR    12
#define DNS_TYPE_HINFO  13
#define DNS_TYPE_MINFO  14
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_SRV    33 /* RFC 2782 */

/* QTYPE values used in queries (TYPE values are also valid) */
#define DNS_QTYPE_AXFR  252
#define DNS_QTYPE_MAILB 253
#define DNS_QTYPE_MAILA 254
#define DNS_QTYPE_ANY   255

/* CLASS values used in Resource Records and queries */
#define DNS_CLASS_IN    1
#define DNS_CLASS_CS    2
#define DNS_CLASS_CH    3
#define DNS_CLASS_HS    4

/* QCLASS value used in queries (CLASS values are also valid) */
#define DNS_QCLASS_ANY  255

#define DNS_MAX_LABEL_LEN 63

#define DNS_MAX_NAME_LEN 256

/* The RDATA portion of a SRV RR (RFC 2782) */
typedef struct {
    uint16_t Priority;
    uint16_t Weight;
    uint16_t Port;
    uint8_t  Target[];
} DNSSRVRRData;

typedef struct {
    uint32_t ADDRESS;
} DNSARRData;

#endif
