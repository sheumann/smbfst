#ifndef MOUNTSMBVOL_H
#define MOUNTSMBVOL_H

#include <uchar.h>
#include <stdint.h>
#include <types.h>
#include "cdev/addressparser.h"

unsigned MountSMBVolumes(AddressParts *address, LongWord sessionID);
Word MountVolume(char16_t *shareName, uint16_t shareNameSize,
    char *volName, AddressParts *address, LongWord sessionID);

#endif
