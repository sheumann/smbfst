#include "defs.h"
#include <time.h>
#include <misctool.h>
#include "helpers/datetime.h"
#include "session.h"
#include "connection.h"

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
 * Convert SMB FILETIME (count of 100 nanosecond intervals since Jan 1, 1601)
 * to ProDOS date/time format.
 */
ProDOSTime GetProDOSTime(uint64_t filetime, Session *session) {
    static union {
        TimeRec timeRec;
        ProDOSTime pdosTime;
    } time;
    
    time.timeRec = GetGSTime(filetime, session);
    ConvSeconds(TimeRec2ProDOS, 0, (Pointer)&time);
    
    return time.pdosTime;
}