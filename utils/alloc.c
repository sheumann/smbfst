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
#include <stddef.h>
#include <memory.h>
#include <orca.h>
#include "utils/alloc.h"

void *smb_malloc(size_t size) {
    Handle handle;
    Word attributes = attrLocked | attrFixed | attrNoSpec;
    
    if (size < 0x10000)
        attributes |= attrNoCross;
    
    /*
     * First try to allocate in bank $E0 or $E1 to avoid fragmenting regular
     * memory.  If that fails, just allocate anywhere non-special.
     */
    handle = NewHandle(size, userid(), attributes | attrBank, (void*)0xE00000);
    if (!toolerror())
        return *handle;

    handle = NewHandle(size, userid(), attributes | attrBank, (void*)0xE10000);
    if (!toolerror())
        return *handle;

    handle = NewHandle(size, userid(), attributes, 0);
    if (!toolerror())
        return *handle;

    return 0;
}


void smb_free(void *ptr) {
    if (ptr == NULL)
        return;

    DisposeHandle(FindHandle(ptr));
}
