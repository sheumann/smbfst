#ifndef CONFIGFILE_H
#define CONFIGFILE_H

#include "cdev/addressparser.h"

void GetSavedLoginInfo(AddressParts *addressParts);
void SaveLoginInfo(char *host, char *domain, char *username, char *password);
void DeleteLoginInfo(char *host);

#endif
