/*
 * Copyright (c) 2024 Stephen Heumann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "defs.h"
#include <time.h>
#include <misctool.h>
#include <orca.h>
#include "helpers/datetime.h"
#include "smb2/session.h"
#include "smb2/connection.h"

typedef union {
    TimeRec timeRec;
    ProDOSTime pdosTime;
} TimeUnion;

static TimeUnion timeUnion;

// Seconds from 1 Jan 1904 (ConvSeconds base) to 13 Nov 1969 (ORCA/C (time_t)0)
#define CONVSECONDS_TIME_OFFSET 2078611200ul

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

    // Use ConvSeconds if possible, because it is faster than localtime.
    if (time <= 0xFFFFFFFF - CONVSECONDS_TIME_OFFSET) {
        ConvSeconds(secs2TimeRec, time + CONVSECONDS_TIME_OFFSET,
            (Pointer)&timeRec);
    } else {    
        // Convert to struct tm
        tm = localtime(&time);
        
        timeRec.weekDay = tm->tm_wday + 1;
        timeRec.month = tm->tm_mon;
        timeRec.day = tm->tm_mday - 1;
        timeRec.year = tm->tm_year;
        timeRec.hour = tm->tm_hour;
        timeRec.minute = tm->tm_min;
        timeRec.second = tm->tm_sec;
    }
    
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

