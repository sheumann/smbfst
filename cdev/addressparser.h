#ifndef ADDRESSPARSER_H
#define ADDRESSPARSER_H

#include <stdbool.h>
#include <stdint.h>

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
    bool anonymous;
    unsigned char *ntlmv2Hash;
    uint32_t knownIP;
} AddressParts;


AddressParts ParseAddress(char *addr);

#endif
