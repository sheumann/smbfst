#include "defs.h"
#include <memory.h>
#include <orca.h>
#include "utils/alloc.h"

void *smb_malloc(size_t size) {
    Handle handle;
    Word attributes = attrLocked | attrFixed | attrNoSpec;
    
    if (size < 0x10000)
        attributes |= attrNoCross;
    
    /*
     * First try to allocate in bank $E0 or $E1 to avoid fragmenting regular
     * memory.  If that fails, just allocate anywhere non-special.
     */
    handle = NewHandle(size, userid(), attributes | attrBank, (void*)0xE00000);
    if (!toolerror())
        return *handle;

    handle = NewHandle(size, userid(), attributes | attrBank, (void*)0xE10000);
    if (!toolerror())
        return *handle;

    handle = NewHandle(size, userid(), attributes, 0);
    if (!toolerror())
        return *handle;

    return 0;
}


void smb_free(void *ptr) {
    DisposeHandle(FindHandle(ptr));
}
