#ifndef P_UTILS_H
#define P_UTILS_H

#include <dirent.h>
#include "targets.h"

//Constants
#define MAX_FNAME_SIZE 32
#define PROC "/proc/"
#define CMDLINE "/proc/%s/cmdline"

/* Filter to identify /proc/ subdirs as PIDs */
static int filter(const struct dirent *dir);

/*  Get all pids associated with Targets and populate the struts */
void getTargetPids(Target targets[MAX_TARGETS]);

#endif /* P_UTILS_H  */

