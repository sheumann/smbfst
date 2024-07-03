#ifndef MDNS_H
#define MDNS_H

#include <stdbool.h>
#include <stdint.h>
#include <types.h>

typedef struct {
    uint16_t port;
    uint32_t address;
    uint8_t *hostName; // fully-expanded DNS name
    uint8_t name[64];  // p-string, UTF-8
} ServerInfo;

typedef void ServerHandler(ServerInfo *);

void MDNSSDProcessPacket(Handle packetHandle, ServerHandler *handler);

void MDNSSDInitQuery(const uint8_t *queryName);

void MDNSSDSendQuery(Word ipid);

Long MDNSResolveName(char *name);

#endif
