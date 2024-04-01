#ifndef FILETYPE_H
#define FILETYPE_H

#include <types.h>
#include <stdbool.h>
#include "driver.h"
#include "helpers/afpinfo.h"

typedef struct {
   Word fileType;
   LongWord auxType;
} FileType;

/*
 * Determine the file type/auxtype, based on an AFPInfo structure
 * for the file, or the file name in the GS/OS DP.
 */
FileType GetFileType(struct GSOSDP *gsosdp, AFPInfo *afpInfo, bool isDirectory);

#endif
