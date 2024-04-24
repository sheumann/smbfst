#ifndef SRVSVCPROTO_H
#define SRVSVCPROTO_H

#include <stdint.h>
#include "rpc/ndr.h"

/*
 * Definitions for srvsvc data structures.  See [MS-SRVS].
 *
 * This defines just the elements that we need and use, not the fully general
 * forms of the srvsvc structures.
 */

#define NetrShareEnum_opnum 15

#define LEVEL_1 1

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
    NDR_PTR(char16_t[]) shi1_netname;
    uint32_t shi1_type;
    NDR_PTR(char16_t[]) shi1_remark;
} SHARE_INFO_1;

typedef struct {
    uint32_t EntriesRead;
    NDR_PTR(SHARE_INFO_1[EntriesRead]) Buffer;
} SHARE_INFO_1_CONTAINER;

typedef union {
    NDR_PTR(SHARE_INFO_1_CONTAINER) Level1;
    //other levels omitted
} SHARE_ENUM_UNION;

typedef struct {
    uint32_t Level;
    NDR_UNION(SHARE_ENUM_UNION) ShareInfo;
} SHARE_ENUM_STRUCT;

#endif
