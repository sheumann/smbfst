/*
 * Copyright (c) 2024 Stephen Heumann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
