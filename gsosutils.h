#include <gsos.h>

/* GS/OS string and result buf types.
 *
 * These are not really limited to 255 characters.  That's just how the
 * structures are specified in the C headers.
 */
typedef ResultBuf255 ResultBuf;
typedef ResultBuf255Ptr ResultBufPtr;
typedef GSString255 GSString;
typedef GSString255Ptr GSStringPtr;

Word WriteGSOSString(Word length, char *str, ResultBufPtr buf);
Word WritePString(Word length, char *str, char *buf);
