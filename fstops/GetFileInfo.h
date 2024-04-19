#ifndef GETFILEINFO_H
#define GETFILEINFO_H

#include <types.h>
#include "smb2/smb2proto.h"
#include "smb2/fileinfo.h"

extern FILE_BASIC_INFORMATION basicInfo;
extern bool haveDataForkSizes;
extern uint64_t dataEOF, dataAlloc;

Word GetFileInfo_Impl(void *pblock, struct GSOSDP *gsosdp, Word pcount,
    bool alreadyOpen, SMB2_FILEID fileID);

#endif
