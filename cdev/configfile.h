#ifndef CONFIGFILE_H
#define CONFIGFILE_H

#include <types.h>
#include "cdev/addressparser.h"

/*
 * Login Info data structure.
 * buf contains domain, then user and password at designated offsets
 * (all C strings).
 */
typedef struct {
    Word userOffset;
    Word passwordOffset;
    char buf[3 * 256 + 1];
} LoginInfo;

void GetSavedLoginInfo(AddressParts *addressParts);
void SaveLoginInfo(char *host, char *domain, char *username, char *password);
void SaveAutoMountList(char *host, Handle listHandle);
Long DeleteSavedInfo(char *host, bool deleteLoginInfo,
    bool deleteAutoMountList);
void ForEachAutoMountList(void (*f)(Handle,Handle,char*));

#endif
