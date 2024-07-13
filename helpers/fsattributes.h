#ifndef FSATTRIBUTES_H
#define FSATTRIBUTES_H

#include <stdint.h>
#include "driver/dib.h"
#include "smb2/smb2proto.h"

uint32_t GetFSAttributes(DIB *dib, const SMB2_FILEID *fileID);

#endif
