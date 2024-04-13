#ifndef STARTUP_H
#define STARTUP_H

enum MarinettiStatus {tcpipUnloaded, tcpipLoaded, tcpipLoadError};

extern enum MarinettiStatus marinettiStatus;

#endif
