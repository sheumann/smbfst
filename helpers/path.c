#include "defs.h"
#include <string.h>
#include <uchar.h>
#include <stdbool.h>
#include <gsos.h>
#include "helpers/path.h"

static char16_t macRomanToUCS2[128] = {
    /* 80-87 */ 0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1,
    /* 88-8f */ 0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9, 0x00E8,
    /* 90-97 */ 0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1, 0x00F3,
    /* 98-9f */ 0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB, 0x00FC,
    /* a0-a7 */ 0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6, 0x00DF,
    /* a8-af */ 0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x00C6, 0x00D8,
    /* b0-b7 */ 0x221E, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x00B5, 0x2202, 0x2211,
    /* b8-bf */ 0x220F, 0x03C0, 0x222B, 0x00AA, 0x00BA, 0x03A9, 0x00E6, 0x00F8,
    /* c0-c7 */ 0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206, 0x00AB,
    /* c8-cf */ 0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152, 0x0153,
    /* d0-d7 */ 0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7, 0x25CA,
    /* d8-df */ 0x00FF, 0x0178, 0x2044, 0x00A4, 0x2039, 0x203A, 0xFB01, 0xFB02,
    /* e0-e7 */ 0x2021, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA, 0x00C1,
    /* e8-ef */ 0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3, 0x00D4,
    /* f0-f7 */ 0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x02C6, 0x02DC,
    /* f8-ff */ 0x00AF, 0x02D8, 0x02D9, 0x02DA, 0x00B8, 0x02DD, 0x02DB, 0x02C7
};

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
            if (ch & 0x80)
                ch = macRomanToUCS2[ch & 0x7f];
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
            case 0xF028:
                ch = '|';
                break;
            }
        } else {
            //TODO maybe limit to characters in Shaston 8?
            for (i = 0; i < ARRAY_LENGTH(macRomanToUCS2); i++) {
                if (macRomanToUCS2[i] == ch) {
                    ch = i & 0x80;
                    break;
                }
            }
            if (i == ARRAY_LENGTH(macRomanToUCS2))
                mapped = false;
        }
        
        if (mapped) {
            if (outputLength < bufSize) {
                *outPtr++ = ch;
            }
            outputLength++;
        } else {
            // TODO generate escape sequences for arbitrary Unicode chars
            if (outputLength < bufSize) {
                *outPtr++ = '?';
            }
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
