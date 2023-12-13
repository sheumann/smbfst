/*
 * File information data structures.
 *
 * See [MS-FSCC].
 */

#include <stdint.h>

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
        uint16_t FileName[];
} FILE_DIRECTORY_INFORMATION;
