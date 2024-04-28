#include "defs.h"

#include <gsos.h>
#include <tcpip.h>
#include <orca.h>
#include <string.h>
#include "fst/fstspecific.h"
#include "smb2/smb2.h"
#include "utils/alloc.h"
#include "systemops/Startup.h"

Word SMB_Connect(SMBConnectRec *pblock, void *gsosdp, Word pcount) {
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
    
    result = Connect(connection);
    if (result) {
        smb_free(connection);
        return result;
    }
    
    connection->refCount = 1;
    pblock->connectionID = (LongWord)connection;
    return 0;
}
