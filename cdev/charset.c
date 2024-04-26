#include "defs.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cdev/charset.h"
#include "utils/macromantable.h"

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
