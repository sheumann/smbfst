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
#include <memory.h>
#include <orca.h>
#include "utils/buffersize.h"

static Handle purgeableBufferHandle = 0;
static uint16_t allowedSize = 0;

// Maximum size we will allocate if possible
#define MAX_ALLOC_SIZE 65536

// Minimum size we will try to allocate
#define MIN_ALLOC_SIZE 512

/*
 * Determine the size of buffers that should be OK to use for TCP/IP
 * operations, based on the available free memory.  This will be
 * less than or equal to the desired value passed in.  In situations
 * where available memory is critically low, 0 may be returned.
 *
 * This is based on a heuristic that Marinetti generally seems to work
 * OK if twice the buffer size is available as an allocatable block
 * of non-special memory.  (This is a heuristic based on Marinetti's
 * observed behavior, not an absolute guarantee.)
 
 * We use a technique along the lines suggested in Apple IIGS TN #51,
 * using a purgeable handle to check for low memory situations.
 */
uint16_t GetBufferSize(size_t desiredSize) {
    size_t allocSize;

    // Check if handle has been purged
    if (*purgeableBufferHandle == NULL)
        allowedSize = 0;

    // If we have enough space to satisfy the request, just return
    if (desiredSize <= allowedSize)
        return desiredSize;

    // If we are here, we would like more space.  See if it's available.
    PurgeHandle(purgeableBufferHandle);
    allowedSize = 0;

    for (allocSize = MAX_ALLOC_SIZE; allocSize >= MIN_ALLOC_SIZE;
        allocSize >>= 1) {
        ReAllocHandle(allocSize, userid(), attrNoSpec | attrPurge1, 0,
            purgeableBufferHandle);
        if (!toolerror()) {
            allowedSize = allocSize / 2;
            break;
        }
    }
    
    return min(desiredSize, allowedSize);
}

bool InitBufferSize(void) {
    purgeableBufferHandle = NewHandle(0, userid(), attrNoSpec | attrPurge1, 0);
    return !toolerror();
}
