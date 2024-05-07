#ifndef MDNSPROTO_H
#define MDNSPROTO_H

#include "mdns/dnsproto.h"

/* Bit of QCLASS set to indicated a unicast response is desired in MDNS */
#define MDNS_FLAG_QU    0x8000

#define MDNS_MAX_PACKET_SIZE 9000 /* including IP and UDP headers */

#define MDNS_IP 0xFB0000E0 /* 224.0.0.251 */
#define MDNS_PORT 5353

#endif
