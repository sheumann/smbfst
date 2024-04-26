#ifndef CHARSET_H
#define CHARSET_H

#include <stdint.h>
#include <uchar.h>

typedef struct {
    uint16_t length; // length of text in bytes
    char16_t text[];
} UTF16String;

UTF16String *MacRomanToUTF16(char *str);

#endif
