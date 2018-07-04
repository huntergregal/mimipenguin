#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "util.h"

char *getUserHash(char *user)
{
    FILE *fp = NULL;
    char *line = NULL, *ret = NULL;
    char *chunk = NULL;
    size_t lineSize = 0, chunkSize = 0;
    int nameEnd = 0;

    if ( (fp = fopen(SHADOW, "r")) == NULL )
    {
        printf("  [!] ERROR: Failed to open /etc/shadow - %s\n", strerror(errno));
        goto CLEANUP;
    }

    while ( getline(&line, &lineSize, fp) >= 0 )
    {
        chunk = line;
        for (int i=0; i < strlen(chunk); i++)
        {
            if ( chunk[i] == ':' )
            {
                nameEnd = i+1; // Save this spot
                chunk[i] = 0x00; // Null terminate the user string
                break; // break for
            }
        }

        if ( !strcmp(user, chunk) ) // found the target user
        {
            chunk += nameEnd; // Slide up to next chunk (the hash)
            for (int i=0; i < strlen(chunk); i++)
            {
                if ( chunk[i] == ':' )
                {
                    chunk[i] = '\0'; // Null terminate the hash string
                    break; // break for
                }
            }
            if ( (ret = calloc(strlen(chunk)+1, 1)) == NULL )
            {
                printf("  [!] ERROR: calloc failed - %s\n", strerror(errno));
                goto CLEANUP;
            }

            memcpy(ret, chunk, strlen(chunk));
            break; // break while
        }

        NEXT:
            if ( line != NULL )
            {
                free(line);
                line = NULL;
            }
            lineSize = 0;
    }

    CLEANUP:
        if ( fp != NULL )
            fclose(fp);
        if ( line != NULL )
            free(line);
        return ret;
}

char *getSalt(char *hash)
{
    int len = 0, count = 0;
    char *ret = NULL;
    for (int i=0; i < strlen(hash); i++)
    {
        if ( hash[i] == '$' )
            count += 1;
        if ( count == 3 )
        {
            len = i; // $1$
            break;
        }
    }
    ret = calloc(len+1, 1);
    memcpy(ret, (hash), len);
    return ret;
}

int checkPasswd(char *user, char *passwd)
{
    char *hash = NULL;
    char *testHash = NULL;
    char *salt= NULL;
    int ret = -1;

    if ( (hash = getUserHash(user)) == NULL )
    {
        printf("  [!] Failed getting user hash\n");
        goto CLEANUP;
    }

    salt = getSalt(hash);
    if ( (testHash = crypt(passwd, salt)) == NULL )
    {
        printf("  [!] ERROR creating crypt hash - %s\n", strerror(errno));
        goto CLEANUP;
    }

    if ( !strcmp(hash, crypt(passwd, salt)) )
        ret = 1;
    else
        ret = 0;

    //printf("user:%s\nsalt:%s\nhash: %s\n", user, salt, hash);
    CLEANUP:
        if ( hash != NULL )
            free(hash);
        if ( salt != NULL )
            free(salt);
        return ret;
}

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

