#ifndef ADDRESSPARSER_H
#define ADDRESSPARSER_H

#include <stdbool.h>

typedef struct {
    char *domain;
    char *username;
    char *password;
    char *host;
    char *port;
    char *share;
    char *path; /* Omits leading '/'. */
    
    char *displayName;
    
    bool errorFound;
    bool usingSavedLoginInfo;
} AddressParts;


AddressParts ParseAddress(char *addr);

#endif
