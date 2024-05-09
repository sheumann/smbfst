#ifndef DEFS_H
#define DEFS_H

#ifdef __ORCAC__
#pragma lint -1
#pragma ignore 24
#ifndef USE_BLANK_SEG
segment "AUTOSEG~~~";
#endif
#ifndef GENERATE_ROOT
#pragma noroot
#endif
#endif

#ifdef __ORCAC__
#define UNIMPLEMENTED asm {brk 0}
#else
#define UNIMPLEMENTED
#endif

#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))

#define ARRAY_LENGTH(a) (sizeof(a)/sizeof(*(a)))

/* Marinetti buffer types */
#define buffTypePointer 0x0000
#define buffTypeHandle 0x0001
#define buffTypeNewHandle 0x0002

#endif
