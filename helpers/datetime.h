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

#ifndef DATETIME_H
#define DATETIME_H

#include <types.h>
#include <stdint.h>
#include "smb2/session.h"

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
uint64_t CurrentTime(Session *session);

#endif
