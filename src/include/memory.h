#ifndef MEMORY_H
#define MEMORY_H

#include <fcntl.h>
#include <sys/stat.h>
#include "targets.h"

//Constants
#define ATTS_SIZE 5
#define MAPS "/proc/%d/maps"

/* Public processing function. Used to process the memory for all targets and pids */
void processTargets(Target targets[MAX_TARGETS]);

/* Process a memory region for needles and potential passwords */
void processRegion(int fd, off_t start, off_t end);

/* Identifies readable regions of memory for the target pid */
void processMemory(Target target, pid_t pid);
#endif /* MEMORY_H */
