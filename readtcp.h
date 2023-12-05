#include <stdint.h>
#include <types.h>

typedef enum {
    rsDone,
    rsMoreProcessingRequired,
    rsError,
    rsTimedOut
} ReadStatus;

ReadStatus ReadTCP(Word ipid, uint16_t size, void *buf);
