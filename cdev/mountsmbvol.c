#include "defs.h"
#include <stdlib.h>
#include <gsos.h>
#include <orca.h>
#include "cdev/mountsmbvol.h"
#include "cdev/charset.h"
#include "cdev/errorcodes.h"
#include "fst/fstspecific.h"

static SMBMountRec mountPB = {
    .pCount = 6,
    .fileSysID = smbFSID,
    .commandNum = SMB_MOUNT,
};

ResultBuf32 devName = {32};
ResultBuf255 volName = {255};

DInfoRec dInfoPB = {
    .pCount = 2,
    .devName = &devName,
};

VolumeRec volumePB = {
    .pCount = 2,
    .devName = &devName.bufString,
    .volName = &volName,
};

unsigned MountSMBVolumes(char *share, LongWord sessionID) {
    UTF16String *shareName = NULL;
    unsigned result = 0;

    if (share == NULL || share[0] == '\0') {
        // TODO prompt for share names
        return 0;
    }
    
    shareName = MacRomanToUTF16(share);
    if (shareName == NULL)
        return oomError;
    
    mountPB.sessionID = sessionID;
    mountPB.shareName = shareName->text;
    mountPB.shareNameSize = shareName->length;
    FSTSpecific(&mountPB);
    if (toolerror()) {
        result = mountError;
        goto cleanup;
    }

    dInfoPB.devNum = mountPB.devNum;
    DInfo(&dInfoPB);
    if (toolerror()) {
        result = mountError;
        goto cleanup;
    }

    // This call ensures the share is recognized as an online volume.
    VolumeGS(&volumePB);

cleanup:
    free(shareName);

    return result;
}
