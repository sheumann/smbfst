#ifndef ALLOC_H
#define ALLOC_H

#include <stddef.h>

void *smb_malloc(size_t size);
void smb_free(void *ptr);

#endif
