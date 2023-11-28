#ifdef __ORCAC__
#pragma lint -1
#pragma ignore 24
#endif

#ifdef __ORCAC__
#define UNIMPLEMENTED asm {brk 0}
#else
#define UNIMPLEMENTED
#endif
