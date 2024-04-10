#include "defs.h"
#include <time.h>
#include <misctool.h>
#include <orca.h>
#include "helpers/datetime.h"
#include "session.h"
#include "connection.h"

typedef union {
    TimeRec timeRec;
    ProDOSTime pdosTime;
} TimeUnion;

static TimeUnion timeUnion;

// TODO Rework these functions to work over the whole range of GS/OS TimeRec
//      (i.e. avoid dependency on 32-bit time_t).

/*
 * Convert SMB FILETIME (count of 100 nanosecond intervals since Jan 1, 1601)
 * to GS/OS TimeRec (ReadTimeHex format).
 */
TimeRec GetGSTime(uint64_t filetime, Session *session) {
    static TimeRec timeRec = {0};
    time_t time;
    struct tm *tm;
    
    filetime += session->connection->timeDiff;

    // If time is out of range for time_t, just return a TimeRec of all zeros.
    if (filetime < TIME_T_0 || filetime > TIME_T_MAX)
        return timeRec;

    // Convert to time_t format
    time = (filetime - TIME_T_0) / 10000000;
    
    // Convert to struct tm
    tm = localtime(&time);
    
    timeRec.weekDay = tm->tm_wday + 1;
    timeRec.month = tm->tm_mon;
    timeRec.day = tm->tm_mday - 1;
    timeRec.year = tm->tm_year;
    timeRec.hour = tm->tm_hour;
    timeRec.minute = tm->tm_min;
    timeRec.second = tm->tm_sec;
    
    return timeRec;
}

/*
 * Convert SMB FILETIME to ProDOS date/time format.
 */
ProDOSTime GetProDOSTime(uint64_t filetime, Session *session) {
    timeUnion.timeRec = GetGSTime(filetime, session);
    ConvSeconds(TimeRec2ProDOS, 0, (Pointer)&timeUnion);
    
    return timeUnion.pdosTime;
}

/*
 * Convert GS/OS TimeRec to SMB FILETIME.
 */
uint64_t GSTimeToFiletime(TimeRec timeRec, Session *session) {
    static struct tm tm;
    time_t time;
    
    tm.tm_mon = timeRec.month;
    tm.tm_mday = timeRec.day + 1;
    tm.tm_year = timeRec.year;
    tm.tm_hour = timeRec.hour;
    tm.tm_min = timeRec.minute;
    tm.tm_sec = timeRec.second;

    time = mktime(&tm);
    
    return TIME_T_0 + (uint64_t)time * 10000000 - session->connection->timeDiff;
}

/*
 * Convert ProDOS date/time format to SMB FILETIME.
 */
uint64_t ProDOSTimeToFiletime(ProDOSTime time, Session *session) {
    timeUnion.pdosTime = time;
    ConvSeconds(ProDOS2TimeRec, 0, (Pointer)&timeUnion);
    if (toolerror())
        return 0;
    
    return GSTimeToFiletime(timeUnion.timeRec, session);
}

/*
 * Return current time in SMB FILETIME format.
 */
uint64_t CurrentTime(Session *session) {
    return TIME_T_0 + 
        (uint64_t)time(NULL) * 10000000 - session->connection->timeDiff;
}

