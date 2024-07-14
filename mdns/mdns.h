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

#ifndef MDNS_H
#define MDNS_H

#include <stdbool.h>
#include <stdint.h>
#include <types.h>

typedef struct {
    uint16_t port;
    uint32_t address;
    char *hostName; // fully-expanded DNS name
    uint8_t name[64];  // p-string, UTF-8
} ServerInfo;

typedef void ServerHandler(ServerInfo *);

void MDNSSDProcessPacket(Handle packetHandle, ServerHandler *handler);

void MDNSSDInitQuery(const uint8_t *queryName);

void MDNSSDSendQuery(Word ipid);

Long MDNSResolveName(char *name);

#endif
