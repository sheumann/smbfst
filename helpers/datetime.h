#ifndef DATETIME_H
#define DATETIME_H

#include <types.h>
#include <stdint.h>
#include "session.h"

// FILETIME corresponding to (time_t)0 in ORCA/C (Nov 13, 1969)
#define TIME_T_0 116402400000000000

// FILETIME corresponding to maximum value representable with time_t in ORCA/C
#define TIME_T_MAX (TIME_T_0 + 0xFFFFFFFFull * 10000000)

// Convert a time_t value to FILETIME
#define TIME_TO_FILETIME(x) ((x) * 10000000ull + TIME_T_0)

typedef struct {
    Word date;
    Word time;
} ProDOSTime;

TimeRec GetGSTime(uint64_t filetime, Session *session);
ProDOSTime GetProDOSTime(uint64_t filetime, Session *session);
uint64_t GSTimeToFiletime(TimeRec timeRec, Session *session);
uint64_t ProDOSTimeToFiletime(ProDOSTime time, Session *session);

#endif
