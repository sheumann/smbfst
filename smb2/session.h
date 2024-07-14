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

#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <types.h>
#include "smb2/connection.h"
#include "driver/dib.h"
#include "auth/auth.h"

struct hmac_sha256_context;

typedef struct {
    Connection *connection;

    uint64_t sessionId; // TODO separate session structure?
    
    bool signingRequired;
    
    // If signingRequired is true, this points to either a
    // struct hmac_sha256_context (SMB 2.x) or struct aes_cmac_context (3.x).
    void *signingContext;
    
    Word refCount;
    
    AuthInfo authInfo;
    
    bool established;
} Session;

extern Session sessions[NDIBS];

void Session_Retain(Session *sess);
void Session_Release(Session *sess);
Session *Session_Alloc(void);
Word SessionSetup(Session *session);
Word Session_Reconnect(Session *session);

#endif
