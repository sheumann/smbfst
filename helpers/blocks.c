#include "defs.h"
#include "helpers/blocks.h"

/*
 * Get the number of blocks consumed by a given size.
 *
 * Note: This currently uses our assumed block size, not necessarily the
 * real value on the server.
 */
uint32_t GetBlockCount(uint64_t size) {
        uint64_t blocks = size / BLOCK_SIZE;
        if (size & (BLOCK_SIZE - 1))
                blocks++;
        return min(blocks, 0xFFFFFFFF);
}
