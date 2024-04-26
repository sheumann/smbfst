#ifndef MOUNTSMBVOL_H
#define MOUNTSMBVOL_H

#include <types.h>
#include "cdev/addressparser.h"

unsigned MountSMBVolumes(AddressParts *address, LongWord sessionID);

#endif
