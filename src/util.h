#ifndef UTIL_H
#define UTIL_H

#define PROC "/proc"
#define MAX_PASSWD 1024
#define MAX_PATH 1024

char *getUser(int pid);
unsigned long getBaseAddr(int pid);
#endif
