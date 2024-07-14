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

#include <gsos.h>
#include <tcpip.h>
#include <orca.h>
#include <string.h>
#include <misctool.h>
#include "fst/fstspecific.h"
#include "smb2/smb2.h"
#include "utils/alloc.h"
#include "systemops/Startup.h"

Word SMB_Connect(SMBConnectRec *pblock, struct GSOSDP *gsosdp, Word pcount) {
    Word result;

    if (pblock->pCount != 7)
        return invalidPcount;

    if (marinettiStatus != tcpipLoaded)
        return drvrNoDevice;

    if (!TCPIPGetConnectStatus() || toolerror())
        return drvrOffLine;

    Connection *connection = smb_malloc(sizeof(Connection));
    if (!connection)
        return outOfMem;
    
    memset(connection, 0, sizeof(Connection));
    connection->serverIP = pblock->serverIP;
    connection->serverPort = pblock->serverPort ? pblock->serverPort : SMB_PORT;
    
    connection->reconnectTime = GetTick();
    
    result = Connect(connection);
    if (result) {
        smb_free(connection);
        return result;
    }
    
    connection->refCount = 1;
    pblock->connectionID = (LongWord)connection;
    return 0;
}
