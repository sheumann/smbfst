#include <stdint.h>
#include <stdbool.h>
#include <types.h>

typedef struct {
    Word ipid;
    
    uint64_t nextMessageId;
    
    uint16_t dialect;
    
    bool signingRequired;
    
    uint64_t sessionId; // TODO separate session structure?
} Connection;
