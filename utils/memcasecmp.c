#include "defs.h"
#include <ctype.h>
#include "utils/memcasecmp.h"

int memcasecmp(const char *s1, const char *s2, size_t n)
{
    if (n == 0)
        return 0;

    while (n > 1 && tolower(*s1) == tolower(*s2)) {
        s1++;
        s2++;
        n--;
    }
    
    return (int)*s1 - (int)*s2;
}
