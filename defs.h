#ifdef __ORCAC__
#pragma lint -1
#pragma ignore 24
#endif

#ifdef __ORCAC__
#define UNIMPLEMENTED asm {brk 0}
#else
#define UNIMPLEMENTED
#endif

/* Marinetti buffer types */
#define buffTypePointer 0x0000
#define buffTypeHandle 0x0001
#define buffTypeNewHandle 0x0002
