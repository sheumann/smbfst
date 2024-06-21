#ifndef FINDERSTATE_H
#define FINDERSTATE_H

#include <stdbool.h>
#include <types.h>

#define FINDER_600 0x0600A000
#define FINDER_601 0x0601A000
#define FINDER_602 0x0602A000
#define FINDER_603 0x0603A000
#define FINDER_604 0x0604A000

/*
 * Maximum size that Finder 6.0.1 - 6.0.3 can display correctly
 * (and without crashing or hanging), as a count of 512-byte blocks.
 */
#define FINDER_601_MAX_DISPLAYABLE_BLOCKS 0xc34ffff /* "99,999.9 MB" */

/*
 * Maximum size that Finder 6.0.4 can display correctly, as a count of
 * 512-byte blocks.
 */
#define FINDER_604_MAX_DISPLAYABLE_BLOCKS 0x33333333

extern Word finderUserID;
extern LongWord finderVersion;

void InstallFinderRequestProc(void);
bool CallIsFromFinder(void *pblock, LongWord minVersion, LongWord maxVersion);

#endif