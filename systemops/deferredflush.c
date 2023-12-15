#include "defs.h"

/*
 * This is called to flush the data at the end of a write-deferral session.
 *
 * We do not actually defer the writes, so there is nothing to do here.
 */
int DeferredFlush(void) {
    return 0;
}
