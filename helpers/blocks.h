#ifndef BLOCKS_H
#define BLOCKS_H

#include <stdint.h>

/*
 * Fake block size of 512, which we currently use for all volumes.
 */
// TODO maybe use real block size
#define BLOCK_SIZE   0x000200

/*
 * Get the number of blocks consumed by a given size.
 *
 * Note: This currently uses our assumed block size, not necessarily the
 * real value on the server.
 */
uint32_t GetBlockCount(uint64_t size);

#endif
