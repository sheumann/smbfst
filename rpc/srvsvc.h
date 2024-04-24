#ifndef SRVSVC_H
#define SRVSVC_H

#include <stdint.h>
#include <uchar.h>

// share type values
#define STYPE_DISKTREE     0x00000000
#define STYPE_PRINTQ       0x00000001
#define STYPE_DEVICE       0x00000002
#define STYPE_IPC          0x00000003
#define STYPE_CLUSTER_FS   0x02000000
#define STYPE_CLUSTER_SOFS 0x04000000
#define STYPE_CLUSTER_DFS  0x08000000

#define STYPE_SPECIAL      0x80000000
#define STYPE_TEMPORARY    0x40000000

typedef struct {
    uint32_t len;   // len includes terminating null
    char16_t str[];
} ShareInfoString;

typedef struct {
    ShareInfoString *shareName;
    uint32_t shareType;
    ShareInfoString *remark;
} ShareInfo;

typedef struct {
    unsigned char reserved[20];
    uint32_t entryCount;
    ShareInfo shares[];
} ShareInfoRec;

Handle EnumerateShares(Word devNum);

#endif
