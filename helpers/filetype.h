#ifndef FILETYPE_H
#define FILETYPE_H

#include <types.h>
#include <stdbool.h>
#include "driver.h"
#include "helpers/afpinfo.h"

#define DIRECTORY_FILETYPE 0x0F

typedef struct {
    Word fileType;
    LongWord auxType;
} FileType;

/*
 * Determine the file type/auxtype, based on an AFPInfo structure
 * for the file, or the file name in the GS/OS DP.
 */
FileType GetFileType(struct GSOSDP *gsosdp, AFPInfo *afpInfo, bool isDirectory);

TypeCreator FileTypeToTypeCreator(FileType type, bool *needSpecificCreator);

#endif
