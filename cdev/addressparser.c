#define USE_BLANK_SEG
#include "defs.h"
#include "cdev/addressparser.h"
#include "cdev/strncasecmp.h"
#include <string.h>

/*
 * Parse a SMB URL and break it up into its component parts.
 *
 * See:
 * https://www.iana.org/assignments/uri-schemes/prov/smb
 * https://datatracker.ietf.org/doc/html/draft-crhertel-smb-url
 */
AddressParts ParseSMBURL(char *url) {
    char *sep, *sep2;
    AddressParts addressParts = {0};

    sep = strrchr(url, '#');
    if (sep) {
        *sep = '\0';
        //addressParts.fragment = sep + 1;
    }

    sep = strchr(url, ':');
    if (sep) {
        //addressParts.scheme = url;
        *sep = '\0';
        url = sep + 1;
    }
    
    if (sep != NULL) {
        if (strncmp(url, "//", 2) == 0) {
            url += 2;
        } else {
            addressParts.errorFound = 1;
            return addressParts;
        }
    }
    
    addressParts.share = strchr(url, '/');
    if (addressParts.share != NULL) {
        *addressParts.share = '\0';
        addressParts.share++;
        
        sep = strchr(addressParts.share, '?');
        if (sep) {
            *sep = '\0';
            //addressParts.query = sep + 1;
        }
        
        sep = strchr(addressParts.share, '//');
        if (sep) {
            *sep = '\0';
            addressParts.path = sep + 1;
        }
    }
    
    sep = strchr(url, '@');
    if (sep) {
        *sep = '\0';
        
        sep2 = strchr(url, ';');
        if (sep2) {
            *sep2 = '\0';
            addressParts.domain = url;
            url = sep2 + 1;
        }

        addressParts.username = url;
        
        addressParts.password = strchr(url, ':');
        if (addressParts.password != NULL) {
            *addressParts.password = '\0';
            addressParts.password++;
        }
        
        url = sep + 1;
    }
    
    addressParts.host = url;
    
    /* Handle IPv6 address syntax */
    if (*url == '[') {
        sep = strchr(url, ']');
        if (sep) {
            url = sep + 1;
        } else {
            addressParts.errorFound = 1;
            return addressParts;
        }
    }
    
    sep = strchr(url, ':');
    if (sep) {
        *sep = '\0';
        addressParts.port = sep + 1;
    }

    return addressParts;
}

/*
 * Parse an address and break it up into its component parts.
 * It can be a smb:// URL, a UNC path, or something of the form
 * server[\share[\path]] or server[/share[/path]].
 *
 * This modifies the string that is passed in.
 */
AddressParts ParseAddress(char *addr) {
    AddressParts addressParts = {0};
    char sepChar;
    char *sep;
    char *pos;
    char *slashPos;
    char *backslashPos;

    if (strncasecmp(addr, "smb://", 6) == 0) {
        // handle SMB URL
        addressParts = ParseSMBURL(addr);
        sepChar = '/';
        goto standardizePath;
    } else if (strncmp(addr, "\\\\", 2) == 0) {
        // handle UNC path
        addr += 2;
        sepChar = '\\';
    } else {
        slashPos = strchr(addr, '/');
        backslashPos = strchr(addr, '\\');
        if (!slashPos) {
            sepChar = '\\';
        } else if (!backslashPos) {
            sepChar = '/';
        } else if (slashPos < backslashPos) {
            sepChar = '/';
        } else {
            sepChar = '\\';
        }
    }
    
    addressParts.host = addr;
    
    sep = strchr(addr, sepChar);
    if (sep) {
        *sep = '\0';
        addressParts.share = sep + 1;
        
        sep = strchr (addressParts.share, sepChar);
        if (sep) {
            *sep = '\0';
            addressParts.path = sep + 1;
        }
    }

standardizePath:
    for (pos = addressParts.path; *pos != '\0'; pos++) {
        if (*pos == sepChar) {
            *pos = '/';
        } else if (*pos == '/' ||  *pos == '\\' || *pos == ':') {
            *pos = '\0';
            addressParts.errorFound = true;
            break;
        }
    }
    
    return addressParts;
}

#ifdef ADDRESSPARSER_TEST
#include <stdio.h>

int main(int argc, char **argv)
{
    AddressParts addressParts;

    if (argc < 2)
        return 1;
    
    addressParts = ParseAddress(argv[1]);
    printf("domain:   %s\n", addressParts.domain ? addressParts.domain : "(NULL)");
    printf("username: %s\n", addressParts.username ? addressParts.username : "(NULL)");
    printf("password: %s\n", addressParts.password ? addressParts.password : "(NULL)");
    printf("host:     %s\n", addressParts.host ? addressParts.host : "(NULL)");
    printf("port:     %s\n", addressParts.port ? addressParts.port : "(NULL)");
    printf("share:    %s\n", addressParts.share ? addressParts.share : "(NULL)");
    printf("path:     %s\n", addressParts.path ? addressParts.path : "(NULL)");
    
    if (addressParts.errorFound) {
        printf("Error found\n");
    }
}
#endif
