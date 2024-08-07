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

#include "defs.h"
#include <misctool.h>
#include <tcpip.h>
#include "gsos/gsosdata.h"
#include "crypto/sha256.h"
#include "utils/random.h"

#define gbuf_ctx ((struct hmac_sha256_context *)gbuf)

static struct hmac_sha256_context state;

static struct {
    TimeRec time;
    Long tick;
    Word videoCounters;
    MouseRec mousePos;
} timeData;

/*
 * Get some data that indicates the time or varies over time.
 */
static void GetTimeData(void) {
    timeData.time = ReadTimeHex();
    timeData.tick = GetTick();
    timeData.videoCounters = *(Word*)0xE0C02E;
    if (MTVersion() >= 0x0300) {
        timeData.mousePos = ReadMouse2();
    } else {
        timeData.mousePos = ReadMouse();
    }
}

/*
 * Feed data that varies over time into the RNG to give additional entropy.
 * (This requires the state to already be in *gbuf_ctx.)
 */
static void AddVariables(void) {
    GetTimeData();
    hmac_sha256_update(gbuf_ctx, (void*)&timeData, sizeof(timeData));
    hmac_sha256_update(gbuf_ctx, (void*)TCPIPGetErrorTable(), sizeof(errTable));
}

/*
 * Initialize the random number generator.
 */
void InitRandom(void) {
    GetTimeData();
    hmac_sha256_init(gbuf_ctx, (void*)&timeData, sizeof(timeData));
    state = *gbuf_ctx;
}

/*
 * Seed RNG state with some entropy (used during start-up).
 */
void SeedEntropy(void) {
    #define bramBuffer ((char*)(gbuf_ctx + 1))

    *gbuf_ctx = state;
    ReadBRam(bramBuffer);
    hmac_sha256_update(gbuf_ctx, (void*)bramBuffer, 0x38);
    hmac_sha256_update(gbuf_ctx, (void*)(bramBuffer + 0x5A), 2);
    hmac_sha256_update(gbuf_ctx, (void*)(bramBuffer + 0x5E), 5);
    hmac_sha256_update(gbuf_ctx, (void*)(bramBuffer + 0x65), 2);
    AddVariables();
    state = *gbuf_ctx;
    
    #undef bramBuffer
}

/*
 * Get a number from the RNG.  Returns a pointer to 32 pseudo-random bytes.
 * Uses gbuf, and returns a pointer within it.
 */
unsigned char *GetRandom(void) {
    *gbuf_ctx = state;
    AddVariables();
    state = *gbuf_ctx;
    hmac_sha256_finalize(gbuf_ctx);
    return hmac_sha256_result(gbuf_ctx);
}
