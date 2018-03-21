#include "targets.h"
#include "pidutils.h"
#include "memory.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    Target targets[MAX_TARGETS];

    initTargets(targets);
    getTargetPids(targets);

    for (int i =0; i < MAX_TARGETS; i++)
    {
        if (targets[i].pids.size > 0)
        {
            printf("[+] FOUND TARGET PROCESS!\n");
            printf("Name: %s\n", targets[i].name);
            printf("Source: %s\n", targets[i].source);
            printf("Needles:\n");
            for (int j =0; j <targets[i].needles.size; j++)
            {
                printf("Needle: %s\n", targets[i].needles.needles[j]);
  
            }
            printf("PIDS:\n");
            for (int j =0; j <targets[i].pids.size; j++)
            {
                printf("PID: %d\n", targets[i].pids.array[j]);
            }
        }
    }
    processTargets(targets);

    return (0);
}

