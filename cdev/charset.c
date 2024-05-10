#define USE_BLANK_SEG
#include "defs.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cdev/charset.h"
#include "utils/macromantable.h"

// SUB (substitute) control code
#define SUB 0x1A

/*
 * Convert a Mac OS Roman string to UTF-16.
 *
 * The returned structure is allocated with malloc; the caller is responsible
 * for freeing it.
 */
UTF16String *MacRomanToUTF16(char *str) {
    size_t len;
    unsigned i;
    UTF16String *utf16Str;
    
    if (str != NULL) {
        len = strlen(str);
    } else {
        len = 0;
    }
    
    if (len > UINT16_MAX / 2)
        return NULL;

    utf16Str = malloc(offsetof(UTF16String, text) + len * 2);
    if (utf16Str == NULL)
        return NULL;

    for (i = 0; i < (unsigned)len; i++) {
        if (str[i] < 128) {
            utf16Str->text[i] = str[i];
        } else {
            utf16Str->text[i] = macRomanToUCS2[str[i] & 0x7F];
        }
    }
    
    utf16Str->length = len * 2;
    
    return utf16Str;
}

/*
 * Convert a UTF-16 string to Mac OS Roman.
 *
 * This converts unrepresentable characters to SUB (0x1A).
 *
 * len is the number of characters in the string, including a terminating null.
 *
 * The returned string is allocated with malloc; the caller is responsible
 * for freeing it.
 */
char *UTF16ToMacRoman(uint32_t len, char16_t utfStr[]) {
    uint32_t i;
    unsigned j;
    char16_t ch;
    char *cStr;

    if (len == 0)
        return NULL;

    // ensure input string is null-terminated
    if (utfStr[len-1] != 0)
        return NULL;

    cStr = malloc(len);
    if (cStr == NULL)
        return NULL;

    for (i = 0; i < len; i++) {
        ch = utfStr[i];
        
        if (ch < 128) {
            cStr[i] = ch;
        } else {
            for (j = 0; j < 128; j++) {
                if (macRomanToUCS2[j] == ch) {
                    cStr[i] = j + 128;
                    break;
                }
            }
            if (j == 128) {
                cStr[i] = SUB;
            }
        }
    }

    return cStr;
}

/*
 * Convert a pstring from UTF-8 to Mac OS Roman in place.
 *
 * This converts unrepresentable characters to SUB (0x1A).
 *
 * Returns true if the input was valid UTF-8, or false if not.
 */
bool UTF8ToMacRoman(unsigned char *str) {
    unsigned len = str[0];
    unsigned in_idx = 1, out_idx = 1;
    char32_t ch;
    unsigned extraBytes;
    unsigned i;
    
    for (; in_idx <= len; in_idx++, out_idx++) {
        if ((str[in_idx] & 0x80) == 0) {
            ch = str[in_idx];
            extraBytes = 0;
        } else if ((str[in_idx] & 0xE0) == 0xC0) {
            extraBytes = 1;
            ch = str[in_idx] & 0x1F;
        } else if ((str[in_idx] & 0xF0) == 0xE0) {
            extraBytes = 2;
            ch = str[in_idx] & 0x0F;
        } else if ((str[in_idx] & 0xF8) == 0xF0) {
            extraBytes = 3;
            ch = str[in_idx] & 0x07;
        } else {
            goto invalid;
        }
        if (len - in_idx < extraBytes)
            goto invalid;

        for (i = 1; i <= extraBytes; i++) {
            if ((str[in_idx + i] & 0xC0) != 0x80)
                goto invalid;
            ch = (ch << 6) | (str[in_idx + i] & 0x3F);
        }
        in_idx += extraBytes;
        
        if (ch < 128) {
            str[out_idx] = ch;
        } else {
            for (i = 0; i < 128; i++) {
                if (macRomanToUCS2[i] == ch) {
                    str[out_idx] = i + 128;
                    break;
                }
            }
            if (i == 128)
                str[out_idx] = SUB;
        }
    }

    str[0] = out_idx - 1;
    return true;

invalid:
    str[out_idx] = SUB;
    str[0] = out_idx;
    return false;
}

