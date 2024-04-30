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
    
    bool errorFound;
} AddressParts;


AddressParts ParseAddress(char *addr);

#endif