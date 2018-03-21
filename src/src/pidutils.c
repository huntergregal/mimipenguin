#include "pidutils.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fnmatch.h>
#include <string.h>

void getTargetPids(Target targets[MAX_TARGETS])
{
    DIR *dirp;
    struct dirent *dp;
    int pidSize;
    char fileName[MAX_FNAME_SIZE], buf[BUFSIZ];
    FILE *fp;
    
    // Open process Dir
    if ((dirp = opendir(PROC)) == 0)
    {
        printf("/proc Access Denied!\n");
        exit(EXIT_FAILURE);
    }

    // Iterate through all processes
    while ((dp = readdir(dirp)) != NULL)
    {
        //If not a pid, skip
        if (fnmatch("[0-9]*", dp->d_name, 0) != 0)
            continue;

        // Get process name
        snprintf(fileName, MAX_FNAME_SIZE, CMDLINE, dp->d_name);
        fp = fopen(fileName, "r");
        if (fp == NULL)
        {
            printf("Could not read /proc/%s/cmdline", dp->d_name);
            exit(EXIT_FAILURE);
        }       
        fgets(buf, BUFSIZ, fp);

  
        //Compare cmdline to target names
        for (int i =0; i < MAX_TARGETS; i++)
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

