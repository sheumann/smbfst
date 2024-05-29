#ifndef CHARSETUTILS_H
#define CHARSETUTILS_H

#include <stdint.h>
#include <uchar.h>

void UTF16ToUpper(char16_t *outStr, const char16_t *inStr, int16_t len);

#endif
