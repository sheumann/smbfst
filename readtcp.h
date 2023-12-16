#ifndef __READTCP_H__
#define __READTCP_H__

#include <stdint.h>
#include <types.h>

typedef enum {
    rsDone,
    rsMoreProcessingRequired,
    rsError,
    rsTimedOut
} ReadStatus;

ReadStatus ReadTCP(Word ipid, uint16_t size, void *buf);

#endif
