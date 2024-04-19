#ifndef ERRORS_H
#define ERRORS_H

#include <types.h>
#include "utils/readtcp.h"

/*
 * Convert an SMB error code to a GS/OS error.
 *
 * If rs == rsFailed, this converts the error code from msg.smb2Header.Status.
 */
Word ConvertError(ReadStatus rs);

#endif
