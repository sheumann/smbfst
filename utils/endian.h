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

#ifndef ENDIAN_H
#define ENDIAN_H

// Endianness conversion macros intended for use with constant expressions

#define hton16c(x) (((uint16_t)(x)<<8) | ((uint16_t)(x)>>8))
#define hton32c(x) (((uint32_t)(x)<<24) | (((uint32_t)(x)&0x0000ff00)<<8) | \
        (((uint32_t)(x)&0x00ff0000)>>8) | ((uint32_t)(x)>>24))
#define hton64c(x) (((uint64_t)(x)<<56) | (((uint64_t)(x)&0x0000ff00)<<40) | \
        (((uint64_t)(x)&0x00ff0000)<<24) | (((uint64_t)(x)&0xff000000)<<8) | \
        (((uint64_t)(x)>>8)&0xff000000) | (((uint64_t)(x)>>24)&0x00ff0000) | \
        (((uint64_t)(x)>>40)&0x0000ff00) | (((uint64_t)(x)>>56)&0x000000ff))

/* TODO assembly versions */
#define hton16(x) hton16c(x)
#define hton32(x) hton32c(x)

#define ntoh16(x) hton16c(x)
#define ntoh32(x) hton32c(x)

#endif
