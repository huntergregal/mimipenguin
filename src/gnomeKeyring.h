#ifndef GNOME_KEYRING_H
#define GNOME_KEYRING_H

#define GNOME_CMD "/usr/bin/gnome-keyring-daemon -V"

typedef struct {
    char *version;
    void *eggPtrAddr;
    int pieFlag;
} GnomeKeyringTarget;

int gnomeKeyringDump(int pid);
#endif
