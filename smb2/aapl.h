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

#ifndef AAPL_H
#define AAPL_H

/*
 * This header covers Apple extensions to the SMB protocol.
 * See: 
 * https://github.com/apple-oss-distributions/SMBClient/blob/SMBClient-438.100.8/kernel/netsmb/smb_2.h
 */

/* Create context name (to be sent in network byte order) */
#define SMB2_CREATE_AAPL 0x4141504C

typedef struct {
    uint32_t CommandCode;
    uint32_t Reserved;
    uint64_t RequestBitmap;
    uint64_t ClientCapabilities;
} AAPL_SERVER_QUERY_REQUEST;

typedef struct {
    uint32_t CommandCode;
    uint32_t Reserved;
    uint64_t ReplyBitmap;
    /*
     * Below fields are present in this order if server caps, volume caps, and
     * model string were all requested.
     */
    uint64_t ServerCapabilities;
    uint64_t VolumeCapabilities;
    uint32_t Pad;
    uint32_t ModelStringLength;
    char16_t ModelString[];
} AAPL_SERVER_QUERY_RESPONSE;

/* Command codes used in AAPL create context */
#define kAAPL_SERVER_QUERY 1
#define kAAPL_RESOLVE_ID   2

/* AAPL Server Query request/response bitmap bits */
#define kAAPL_SERVER_CAPS 0x0000000000000001
#define kAAPL_VOLUME_CAPS 0x0000000000000002
#define kAAPL_MODEL_INFO  0x0000000000000004

/* AAPL client/server capabilities bitmap bits */
#define kAAPL_SUPPORTS_READ_DIR_ATTR    0x0000000000000001
#define kAAPL_SUPPORTS_OSX_COPYFILE     0x0000000000000002
#define kAAPL_UNIX_BASED                0x0000000000000004
#define kAAPL_SUPPORTS_NFS_ACE          0x0000000000000008
#define kAAPL_SUPPORTS_READ_DIR_ATTR_V2 0x0000000000000010
#define kAAPL_SUPPORTS_HIFI             0x0000000000000020

/* AAPL volume capabilities bitmap bits */
#define kAAPL_SUPPORT_RESOLVE_ID 0x0000000000000001
#define kAAPL_CASE_SENSITIVE     0x0000000000000002
#define kAAPL_SUPPORTS_FULL_SYNC 0x0000000000000004

/* Variant of FILE_ID_BOTH_DIR_INFORMATION structure used by AAPL extension */
typedef struct {
    uint32_t NextEntryOffset;
    uint32_t FileIndex;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t EndOfFile;
    uint64_t AllocationSize;
    uint32_t FileAttributes;
    uint32_t FileNameLength;
    
    /* This portion of the structure is modified from the original */
    uint32_t MaxAccess;
    uint8_t  ShortNameLength;
    uint8_t  Reserved1;
    uint64_t RsrcForkLen;
    struct {
        union {
            uint64_t typeCreator;
            uint64_t reserved;
        };
        uint16_t finderFlags;
        uint16_t extFlags;
        uint32_t dateAdded;
    } CompressedFinderInfo;
    uint16_t UnixMode;
    
    uint64_t FileId;
    char16_t FileName[];
} FILE_ID_BOTH_DIR_INFORMATION_AAPL;

#endif
