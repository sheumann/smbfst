#ifndef CLOSEPREVIOUS_H
#define CLOSEPREVIOUS_H

#include "driver/dib.h"
#include "smb2/smb2proto.h"

unsigned EnqueueCloseRequest(DIB *dib, const SMB2_FILEID *fileID);
ReadStatus SendCloseRequestAndGetResponse(DIB *dib, const SMB2_FILEID *fileID);

#endif
