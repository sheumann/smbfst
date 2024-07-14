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
#include "utils/charsetutils.h"

/*
 * Convert a UTF-16 string to upper case.  This is specifically intended
 * to implement the case mapping function used for usernames in NTLMv2,
 * which may differ from other conventions for Unicode case mapping.
 * It currently covers many Latin, Greek, and Cyrillic letters (including
 * all the ones in Mac OS Roman), but it may be missing some obscure ones.
 *
 * len is the length of the input and output buffers in UTF-16 code units.
 * (This function always produces output of the same length as the input.)
 */
void UTF16ToUpper(char16_t *outStr, const char16_t *inStr, int16_t len) {
    uint16_t i;
    char16_t ch;
    
    for (i = 0; i < len; i++) {
        ch = inStr[i];
        if ((ch >= 'a' && ch <= 'z')
            || (ch >= 0x00E0 && ch <= 0x00F6)
            || (ch >= 0x00F8 && ch <= 0x00FE)
            || (ch >= 0x03B1 && ch <= 0x03C1)
            || (ch >= 0x03C3 && ch <= 0x03CB)
            || (ch >= 0x0430 && ch <= 0x044F)) {
            ch -= 32;
        } else if ((ch >= 0x0100 && ch <= 0x012F && (ch & 0x0001))
            || (ch >= 0x0132 && ch <= 0x0137 && (ch & 0x0001))
            || (ch >= 0x0139 && ch <= 0x0148 && (ch & 0x0001) == 0)
            || (ch >= 0x014A && ch <= 0x0177 && (ch & 0x0001))
            || (ch >= 0x0179 && ch <= 0x017E && (ch & 0x0001) == 0)
            || (ch == 0x0183)
            || (ch == 0x0185)
            || (ch == 0x0188)
            || (ch == 0x018C)
            || (ch == 0x0192)
            || (ch == 0x0199)
            || (ch >= 0x01A0 && ch <= 0x01A5 && (ch & 0x0001))
            || (ch == 0x01B4)
            || (ch == 0x01B6)
            || (ch == 0x01B9)
            || (ch == 0x01BD)
            || (ch >= 0x01CD && ch <= 0x01DC && (ch & 0x0001) == 0)
            || (ch >= 0x01DE && ch <= 0x01EF && (ch & 0x0001))
            || (ch == 0x01F5)
            || (ch >= 0x01F8 && ch <= 0x021F && (ch & 0x0001))
            || (ch >= 0x0220 && ch <= 0x0233 && (ch & 0x0001))
            || (ch == 0x023C)
            || (ch == 0x0242)
            || (ch >= 0x0246 && ch <= 0x024F && (ch & 0x0001))
            || (ch == 0x0371)
            || (ch == 0x0373)
            || (ch == 0x0377)
            || (ch == 0x03F8)
            || (ch == 0x03FB)
            || (ch >= 0x0460 && ch <= 0x0481 && (ch & 0x0001))
            || (ch >= 0x048A && ch <= 0x04BF && (ch & 0x0001))
            || (ch >= 0x04C1 && ch <= 0x04CE && (ch & 0x0001) == 0)
            || (ch >= 0x04D0 && ch <= 0x052F && (ch & 0x0001))) {
            ch--;
        } else if (ch == 0x00FF) {
            ch = 0x0178;
        } else if (ch == 0x0180) {
            ch = 0x0243;
        }
        outStr[i] = ch;
    }
}
