#include "targets.h"
#include "memory.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

void processTargets(Target targets[MAX_TARGETS])
{
    for (int i = 0; i < MAX_TARGETS; i++)
    {
        if (targets[i].pids.size > 0)
        {
            for (int j = 0; j < targets[i].pids.size; j ++)
                processMemory(targets[i], targets[i].pids.array[j]);
        }
    }
}

void processRegion(int fd, off_t start, off_t end)
{
    char buf[4096];
 
    lseek(fd, start, SEEK_SET);
    while(start < end) {
        int rd;
 
        rd = read(fd, buf, 4096);

        //search for passwords in region
        //write(STDOUT_FILENO, buf, rd);
        printf("IMPLEMENT SEARCH USING NEEDLES!!!\nmemory.c:34\n");
        exit(0);
        start += 4096;
    }
}

void processMemory(Target target, pid_t pid)
{
    FILE *maps;
    int mem;
    char path[BUFSIZ];

    //Pause/Stop target process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        printf("PTRACE_ATTACH error - Permission denied\n");
        exit(1);
    }

    //Read maps
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    maps = fopen(path, "r");

    //Read memory
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    mem = open(path, O_RDONLY);

    //process memory chunks
    if (maps && mem != -1)
    {
        char buf[BUFSIZ+1];
        char atts[ATTS_SIZE];

        while (fgets(buf, BUFSIZ, maps))
        {
            off_t start, end;

            sscanf(buf, "%llx-%llx %s", &start, &end, atts);
            if (strstr(atts, "r") != NULL) //If region readable
                processRegion(mem, start, end);
        }
    }

    //Resume target process
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if (mem != -1)
        close(mem);
    if (maps)
        fclose(maps);
    
}
