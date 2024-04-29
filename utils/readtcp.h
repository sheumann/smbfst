#ifndef READTCP_H
#define READTCP_H

#include <stdint.h>
#include <types.h>

typedef enum {
    rsDone,
    rsMoreProcessingRequired,
    rsError,
    rsTimedOut,
    rsFailed,   // got a response with a non-success result code
    rsBadMsg,   // msg was at least partially read, but is invalid
} ReadStatus;

ReadStatus ReadTCP(Connection *connection, uint16_t size, void *buf);

#endif
