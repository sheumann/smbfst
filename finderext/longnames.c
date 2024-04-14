/*
 * This is a Finder Extension that patches the Finder to deal slightly
 * better with long file names.
 *
 * The Finder internally limits file names to 32 characters.  Previously,
 * this could result in it displaying garbage and in some cases crashing
 * if it encountered file names longer than that.
 *
 * This patch changes it so that file name are truncated after 32 characters,
 * with ... added at the end.  This prevents the Finder from crashing or
 * displaying garbage.  However, it still cannot open such files or do certain
 * other operations on them, because it does not know the full file name.
 */

#pragma lint -1
#pragma ignore 24

#pragma rtl

#include <finder.h>
#include <locator.h>
#include <memory.h>
#include <stdint.h>
#include <string.h>

#define ARRAY_LENGTH(a) (sizeof(a)/sizeof(*(a)))

#define LDY_ABS 0xAC
#define STY_ABS 0x8C

/* User ID of this program */
Word myUserID;

static char longNamesPatchRequestName[] = "\pSTH~LongNamesPatch~";

#define PATCH_SIZE 6

struct PatchRec {
    uint32_t version;
    uint16_t segmentSize;
    uint16_t patchOffset;
};

const struct PatchRec patches[] = {
    {.version = 0x0601A000, .segmentSize = 63935, .patchOffset = 0xF377},
    {.version = 0x0602A000, .segmentSize = 65062, .patchOffset = 0xF7DE},
    {.version = 0x0603A000, .segmentSize = 65194, .patchOffset = 0xF862},
    {.version = 0x0604A000, .segmentSize = 65210, .patchOffset = 0xF872},
};

extern char patchCode[PATCH_SIZE];
char originalCode[PATCH_SIZE];

struct AbsInsn {
    char opcode;
    unsigned arg;
};

extern struct AbsInsn patch1, patch2, patch3;

char *patchLoc = NULL;


void InstallPatch(finderSaysHelloIn *dataIn) {
    unsigned i;
    Handle segHandle;
    
    if (patchLoc != NULL)
        return;

    // Find patch record for current Finder version (if any)
    for (i = 0; i < ARRAY_LENGTH(patches); i++) {
        if (dataIn->versNum == patches[i].version) {
            break;
        }
    }
    if (i == ARRAY_LENGTH(patches))
        return; // no match found

    // Find handle for the Finder segment containing the dataIn record
    segHandle = FindHandle((Pointer)dataIn);
    if (segHandle == nil)
        return;

    // Ensure it has the right size and owner
    if (GetHandleSize(segHandle) != patches[i].segmentSize)
        return;
    if (SetHandleID(0, segHandle) != dataIn->finderUserID)
        return;

    // Get location to patch
    patchLoc = *segHandle + patches[i].patchOffset;

    // Ensure it has the expected instructions
    if (patchLoc[0] != LDY_ABS || patchLoc[3] != STY_ABS) {
        patchLoc = NULL;
        return;
    }
    
    // Patch original instructions into appropriate locations in new code
    patch1 = *(struct AbsInsn*)patchLoc;
    patch2 = *(struct AbsInsn*)(patchLoc+3);
    patch3 = *(struct AbsInsn*)(patchLoc+3);
    
    // Save original code
    memcpy(originalCode, patchLoc, PATCH_SIZE);

    // Install the patch
    memcpy(patchLoc, patchCode, PATCH_SIZE);
}


void UninstallPatch(void) {
    if (patchLoc == NULL)
        return;
    
    // Restore original code
    memcpy(patchLoc, originalCode, PATCH_SIZE);
    patchLoc = NULL;
}


/*
 * Request procedure which may be called by the Finder.
 */
#pragma databank 1
#pragma toolparms 1
static pascal Word requestProc(Word reqCode, Long dataIn, void *dataOut) {
    switch (reqCode) {
    case finderSaysHello:
        InstallPatch((finderSaysHelloIn *)dataIn);
        break;

    case finderSaysGoodbye:
        UninstallPatch();
        break;

    case srqGoAway:
        AcceptRequests(NULL, myUserID, NULL);
        UninstallPatch();
        ((srqGoAwayOut*)dataOut)->resultID = myUserID;
        ((srqGoAwayOut*)dataOut)->resultFlags = 0;
        break;
    
    default:
        return 0;
    }
    
    return 0x8000;
}
#pragma toolparms 0
#pragma databank 0


int main(void) {
    myUserID = MMStartUp();

    AcceptRequests(
        longNamesPatchRequestName, myUserID, (WordProcPtr)&requestProc);
}
