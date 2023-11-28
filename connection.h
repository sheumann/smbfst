#include <stdint.h>
#include <types.h>

typedef struct {
    Word ipid;
    
    uint64_t nextMessageId;
    
    uint16_t Dialect;
    
    uint64_t sessionId; // TODO separate session structure?
} Connection;
