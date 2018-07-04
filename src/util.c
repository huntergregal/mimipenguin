#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "util.h"

unsigned long getBaseAddr(int pid)
{
    char mapsFile[MAX_PATH] = {0};
    FILE *fp = NULL;
    unsigned long ret = 0;
    char *addrStr = NULL;
    size_t size = 0;

    snprintf(mapsFile, MAX_PATH-1, "%s/%d/maps", PROC, pid);

    if ( (fp = fopen(mapsFile, "r")) == NULL )
    {
        printf("  [!] ERROR: Failed to open maps for pid %d - %s\n", pid, strerror(errno));
        goto CLEANUP;
    }

    if ( getdelim(&addrStr, &size, '-', fp) < 0 )
    {
        printf("  [!] ERROR: Failed to read maps from pid %d - %s\n", pid, strerror(errno));
        goto CLEANUP;
    }

    ret = strtoul(addrStr, NULL, 16);

    CLEANUP:
        if ( fp != NULL )
            fclose(fp);
        if ( addrStr != NULL )
            free(addrStr);
        return ret;
}

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

