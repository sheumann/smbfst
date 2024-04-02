#ifndef GETFILEINFO_H
#define GETFILEINFO_H

#include <types.h>
#include "smb2proto.h"
#include "fileinfo.h"

extern FILE_BASIC_INFORMATION basicInfo;

Word GetFileInfo_Impl(void *pblock, void *gsosdp, Word pcount,
    bool alreadyOpen, SMB2_FILEID fileID);

#endif
