#include "targets.h"
#include <stdlib.h>
#include <string.h>

void initTargets(Target targets[MAX_TARGETS])
{
    //GNOME GDM
    strncpy(targets[0].name, "gdm-password", MAX_NAME_SIZE);
    strncpy(targets[0].source, "[SYSTEM - GNOME]", MAX_SOURCE_SIZE);
    targets[0].pids.size = 0;
    targets[0].needles.size = 2;
    targets[0].needles.needles[0] = "^_pammodutil_getpwnam_root_1$";
    targets[0].needles.needles[1] = "^gkr_system_authtok$";

    //GNOME Keyring
    strncpy(targets[1].name, "gnome-keyring-daemon", MAX_NAME_SIZE);
    strncpy(targets[1].source, "[SYSTEM - GNOME]", MAX_SOURCE_SIZE);
    targets[1].pids.size = 0;
    targets[1].needles.size = 2;
    targets[1].needles.needles[0] = "^+libgck\\-1.so\\.0$";
    targets[1].needles.needles[1] = "libgcrypt\\.so\\..+$";

    //VSFTPD
    strncpy(targets[2].name, "vsftpd", MAX_NAME_SIZE);
    strncpy(targets[2].source, "[SYSTEM - VSFTPD]", MAX_SOURCE_SIZE);
    targets[2].pids.size = 0;
    targets[2].needles.size = 1;
    targets[2].needles.needles[0] = "^::.+\\:[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$";

    //SSHD
    strncpy(targets[3].name, "sshd:", MAX_NAME_SIZE);
    strncpy(targets[3].source, "[SYSTEM - SSH]", MAX_SOURCE_SIZE);
    targets[3].pids.size = 0;
    targets[3].needles.size = 1;
    targets[3].needles.needles[0] = "^sudo.+";
}
