#include "defs.h"
#include <ctype.h>
#include <stdint.h>
#include "helpers/filetype.h"

typedef struct {
    uint32_t creator;
    uint32_t type;
    uint16_t fileType;
    uint32_t auxType;
} TypeCreatorMapRec;

typedef struct {
    char *ext;
    uint16_t fileType;
    uint32_t auxType;
} ExtensionMapRec;

// Macros for forming type/creator codes
#define TYPE(a,b,c,d) \
    ((a) | ((uint16_t)(b))<<8 | ((uint32_t)(c))<<16 | ((uint32_t)(d))<<24)
#define CREATOR(a,b,c,d) TYPE((a),(b),(c),(d))

// type/creator to ProDOS type mappings (creator of 0 is wildcard)
// See Programmer's Reference for System 6.0, p. 336
TypeCreatorMapRec typeCreatorMap[] = {
    {CREATOR('p','d','o','s'), TYPE('P','S','Y','S'), 0xFF, 0x0000},
    {CREATOR('p','d','o','s'), TYPE('P','S','1','6'), 0xB3, 0x0000},
    {CREATOR('d','C','p','y'), TYPE('d','I','m','g'), 0xE0, 0x0005},
    {0,                        TYPE('B','I','N','A'), 0x00, 0x0000},
    {0,                        TYPE('T','E','X','T'), 0x04, 0x0000},
    {0,                        TYPE('M','I','D','I'), 0xD7, 0x0000},
    {0,                        TYPE('A','I','F','F'), 0xD8, 0x0000},
    {0,                        TYPE('A','I','F','C'), 0xD8, 0x0001},
};

// file suffix to ProDOS type mappings
ExtensionMapRec suffixMap[] = {
    {"\p.txt",    0x04, 0x0000},
    {"\p.text",   0x04, 0x0000},
    {"\p.gif",    0xC0, 0x8006},
    {"\p.shk",    0xE0, 0x8002},
    {"\p.bxy",    0xE0, 0x8000},
    {"\p.sys16",  0xB3, 0x0000},
    {"\p.fst",    0xBD, 0x0000},
    {"\p.ps",     0xB0, 0x0719},
    {"\p.rez",    0xB0, 0x0015},
    {"\p.c",      0xB0, 0x0008},
    {"\p.cc",     0xB0, 0x0008},
    {"\p.h",      0xB0, 0x0008},
    {"\p.pas",    0xB0, 0x0005},
    {"\p.asm",    0xB0, 0x0003},
    {"\p.mac",    0xB0, 0x0003},
    {"\p.macros", 0xB0, 0x0003},
};

static int DeHex(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/*
 * Determine the file type/auxtype, based on an AFPInfo structure
 * for the file, or the file name.
 */
FileType GetFileType(GSString *name, AFPInfo *afpInfo, bool isDirectory) {
    FileType fileType = {0,0};
    unsigned char *typeCode;
    int hexVal1, hexVal2;
    unsigned i, j;
    char *chPtr;
    
    // Use the directory filetype if this is a directory
    if (isDirectory) {
        fileType.fileType = DIRECTORY_FILETYPE;
        goto done;
    }
    
    // Use the ProDOS type/auxtype in AFPInfo, if provided
    if (afpInfo->prodosType != 0 || afpInfo->prodosAuxType != 0) {
        fileType.fileType = afpInfo->prodosType;
        fileType.auxType = afpInfo->prodosAuxType;
        goto done;
    }

    // Decode special 'pdos' type/creator codes
    if (afpInfo->finderInfo.typeCreator.creator == TYPE('p','d','o','s')) {
        typeCode = (unsigned char*)&afpInfo->finderInfo.typeCreator.type;
        if (typeCode[0] == 'p') {
            fileType.fileType = typeCode[1];
            fileType.auxType = ((uint16_t)typeCode[2]) << 8 | typeCode[3];
            goto done;
        } else if (typeCode[2] == ' ' && typeCode[3] == ' ') {
            hexVal1 = DeHex(typeCode[0]);
            hexVal2 = DeHex(typeCode[1]);
            if (hexVal1 != -1 && hexVal2 != -1) {
                fileType.fileType = (hexVal1 << 4) | hexVal2;
                fileType.auxType = 0;
                goto done;
            }
        }
    }
    
    // Map other known type/creator codes
    for (i = 0; i < ARRAY_LENGTH(typeCreatorMap); i++) {
        if (typeCreatorMap[i].creator == afpInfo->finderInfo.typeCreator.creator
            || typeCreatorMap[i].creator == 0) {
            if (typeCreatorMap[i].type == afpInfo->finderInfo.typeCreator.type)
            {
                fileType.fileType = typeCreatorMap[i].fileType;
                fileType.auxType = typeCreatorMap[i].auxType;
                goto done;
            }
        }
    }
    
    // Map file suffixes
    for (i = 0; i < ARRAY_LENGTH(suffixMap); i++) {
        if (suffixMap[i].ext[0] <= name->length) {
            chPtr = &name->text[name->length - 1];
            for (j = suffixMap[i].ext[0]; j > 0; j--) {
                if (tolower(*chPtr--) != suffixMap[i].ext[j])
                    break;
            }
            if (j == 0) {
                fileType.fileType = suffixMap[i].fileType;
                fileType.auxType = suffixMap[i].auxType;
                goto done;
            }
        }
    }

done:
    return fileType;
}

/*
 * Map ProDOS-style file type to Mac-style type/creator code.
 *
 * If needSpecificCreator is non-null, *needSpecificCreator is set to indicate
 * whether the specific creator code is needed to represent the type.
 */
TypeCreator FileTypeToTypeCreator(FileType type, bool *needSpecificCreator) {
    TypeCreator tc;
    unsigned i;

    if (needSpecificCreator)
        *needSpecificCreator = false;

    tc.creator = CREATOR('p','d','o','s');

    // Map filetypes with specific type/creator code mappings
    for (i = 0; i < ARRAY_LENGTH(typeCreatorMap); i++) {
        if (typeCreatorMap[i].fileType == type.fileType &&
            typeCreatorMap[i].auxType == type.auxType) {
            tc.type = typeCreatorMap[i].type;
            if (typeCreatorMap[i].creator != 0) {
                tc.creator = typeCreatorMap[i].creator;
                if (needSpecificCreator)
                    *needSpecificCreator = true;
            }
            goto done;
        }
    }
    
    // If no specific mapping is found, use general ProDOS mapping
    tc.type = TYPE('p', type.fileType & 0xFF,
        (type.auxType >> 8) & 0xFF, type.auxType & 0xFF);
    if (needSpecificCreator)
        *needSpecificCreator = true;

done:
    return tc;
}
