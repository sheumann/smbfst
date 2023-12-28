#include "defs.h"
#include <gsos.h>
#include "gsosutils.h"

Word WriteGSOSString(Word length, char *str, ResultBufPtr buf) {
    char *outStr;
    Word i;

    if (buf->bufSize < 4)
        return buffTooSmall;

    buf->bufString.length = length;

    if (buf->bufSize - 2 < length)
        return buffTooSmall;
    
    outStr = buf->bufString.text;
    for (i = 0; i < length; i++) {
        outStr[i] = str[i];
    }
    return 0;
}

Word WritePString(Word length, char *str, char *buf) {
    Word i;

    // TODO check how we should handle string-too-long case (maybe truncate?)
    if (length > 255)
        return buffTooSmall;

    buf[0] = length;
    for (i = 0; i < length; i++) {
        buf[i+1] = str[i];
    }
    return 0;
}
