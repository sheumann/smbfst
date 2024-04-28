#include "defs.h"
#include <string.h>
#include <uchar.h>
#include <stdbool.h>
#include <gsos.h>
#include "helpers/path.h"
#include "utils/macromantable.h"

/*
 * This is the mask for the characters that we use to start Unicode escape
 * sequences.  Specifically, we map an untranslatable UTF-16 code unit
 * 0bxxyyyyyyyzzzzzzz to the sequence 0b111111xx 0b1yyyyyyy 0b1zzzzzzz.
 */
#define ESCAPE_CHAR_MASK 0xFC

/*
 * Translate a path from the GS/OS direct page (path1 or path2, indicated by
 * num) to SMB format.  It is written to smbpath, with maximum length bufsize.
 * The size of the resulting path (in bytes) is returned; 0xFFFF indicates an
 * error.
 */
unsigned GSOSDPPathToSMB(
    struct GSOSDP *gsosdp, int num, uint8_t *smbpath, unsigned bufsize) {

    GSString *gspath;
    
    if (num == 1) {
        if ((gsosdp->pathFlag & HAVE_PATH1) == 0)
            return 0;
        gspath = gsosdp->path1Ptr;
    } else {
        if ((gsosdp->pathFlag & HAVE_PATH2) == 0)
            return 0;
        gspath = gsosdp->path2Ptr;
    }

    return GSPathToSMB(gspath, smbpath, bufsize);
}


/*
 * Translate a path from GS/OS format to SMB format.  It is written to smbpath,
 * with maximum length bufsize.  The size of the resulting path (in bytes) is
 * returned; 0xFFFF indicates an error.
 */
unsigned GSPathToSMB(GSString *gspath, uint8_t *smbpath, unsigned bufsize) {
    const char *path;
    unsigned len;
    unsigned out_pos = 0;

    if (gspath->length != 0 && gspath->text[0] == ':') {
        path = memchr(gspath->text + 1, ':', gspath->length - 1);
        if (path == NULL) {
            len = 0;
        } else {
            path++;
            len = gspath->length - (path - gspath->text);
        }
    } else {
        path = gspath->text;
        len = gspath->length;
    }
    
    bufsize &= 0xfffe;
    
    while (len-- > 0) {
        char16_t ch = *path++;

        switch (ch) {
        /* null byte is illegal */
        case 0x00:
            return 0xFFFF;
    
        /*
         * Certain characters are illegal per [MS-FSCC], but can be represented
         * by "SFM" mapping to Unicode private use area codepoints.  See:
         * https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/bsd/vfs/vfs_utfconv.c#L1122
         */
        case 0x01: case 0x02: case 0x03:
        case 0x04: case 0x05: case 0x06: case 0x07:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x0C: case 0x0D: case 0x0E: case 0x0F:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x14: case 0x15: case 0x16: case 0x17:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x1C: case 0x1D: case 0x1E: case 0x1F:
            ch |= 0xF000;
            break;
        case '"':
            ch = 0xF020;
            break;
        case '*':
            ch = 0xF021;
            break;
        case '/':
            ch = 0xF022;
            break;
        case '<':
            ch = 0xF023;
            break;
        case '>':
            ch = 0xF024;
            break;
        case '?':
            ch = 0xF025;
            break;
        case '\\':
            ch = 0xF026;
            break;
        case '|':
            ch = 0xF027;
            break;
        // TODO Map ' ' and '.' at end of name, like macOS does?

        /* Path separator: : -> \ */
        case ':':
            ch = '\\';
            break;

        default:
            if (ch & 0x80) {
                if (ch >= ESCAPE_CHAR_MASK && len >= 2
                    && (path[0] & 0x80) && (path[1] & 0x80)) {
                    // Convert a Unicode escape sequence
                    ch = ((ch & 0x03) << 14) 
                        | ((path[0] & 0x7f) << 7) | (path[1] & 0x7f);
                    len -= 2;
                    path += 2;
                } else {
                    ch = macRomanToUCS2[ch & 0x7f];
                }
            }
        }

        if (out_pos >= bufsize)
            return 0xFFFF;
        *(char16_t*)(smbpath+out_pos) = ch;
        out_pos += 2;
    }
    
    return out_pos;
}

/*
 * Convert an SMB filename to GS/OS representation.
 * Returns a GS/OS error code.
 */
Word SMBNameToGS(char16_t *name, uint16_t length, ResultBuf* buf) {
    char16_t ch;
    unsigned i;
    bool mapped;
    unsigned outputLength;
    unsigned bufSize;
    char *outPtr;
    
    if (length & 0x0001)
        return badPathSyntax;

    length /= 2;

    // Ensure outputLength won't overflow, accounting for Unicode escapes
    if (length > UINT16_MAX / 3)
        return badPathSyntax;
 
    if (buf->bufSize < 4)
        return buffTooSmall;

    bufSize = buf->bufSize - 4;
    outputLength = 0;
    outPtr = buf->bufString.text;

    while (length-- > 0) {
        ch = *name++;

        // Assume character will be successfully mapped
        mapped = true;

        if (ch == 0) {
            buf->bufString.length = 0;
            return badPathSyntax;
        } else if (ch < 0x80) {
            // leave unchanged
        } else if (ch >= 0xF001 && ch <= 0xF01F) {
            ch &= 0x00FF;
        } else if (ch >= 0xF020 && ch <= 0xF027) {
            // TODO Map ' ' and '.' at end of name, like macOS does?
            switch (ch) {
            case 0xF020:
                ch = '"';
                break;
            case 0xF021:
                ch = '*';
                break;
            case 0xF022:
                ch = '/';
                break;
            case 0xF023:
                ch = '<';
                break;
            case 0xF024:
                ch = '>';
                break;
            case 0xF025:
                ch = '?';
                break;
            case 0xF026:
                ch = '\\';
                break;
            case 0xF027:
                ch = '|';
                break;
            }
        } else {
            for (i = 0; i < (ESCAPE_CHAR_MASK & 0x7F); i++) {
                if (macRomanToUCS2[i] == ch) {
                    ch = i | 0x80;
                    break;
                }
            }
            if (i == (ESCAPE_CHAR_MASK & 0x7F))
                mapped = false;
        }
        
        if (mapped) {
            if (outputLength < bufSize)
                *outPtr++ = ch;
            outputLength++;
        } else {
            // Generate escape sequence for an unmapped UTF-16 code unit
            if (outputLength < bufSize)
                *outPtr++ = ESCAPE_CHAR_MASK | (ch >> 14);
            outputLength++;
            if (outputLength < bufSize)
                *outPtr++ = 0x80 | ((ch >> 7) & 0x7f);
            outputLength++;
            if (outputLength < bufSize)
                *outPtr++ = 0x80 | (ch & 0x7f);
            outputLength++;
        }
    }
    
    buf->bufString.length = outputLength;
    
    if (outputLength > bufSize) {
        return buffTooSmall;
    } else {
        return 0;
    }
}
