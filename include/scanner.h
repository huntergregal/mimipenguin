#ifndef SCANNER_H
#define SCANNER_H

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "targets.h"
#include "max.h"

/* Public processing function. Used to process the memory for all targets and pids */
// -1 error, 0 good
int processTargets(Target targets[MAX_TARGETS]);

/* Identifies readable regions of memory for the target pid */
// -1 error, 0 good
int processMemory(Target target, pid_t pid);

// Get a str (like strings command) from fp of min size min_str, and max size max_str. store result in
// **str ptr. cur is a marker for bytes read, max_cur is max amount of bytes to read
// returns -1 or size of string
int getStr(FILE *fp, char *str, size_t min_str, size_t max_str, size_t *cur, size_t max_cur);

/* Process a memory region potential passwords */
// -1 error, 0 good
int processRegion(FILE *fp, unsigned long start, unsigned long end);

#endif /* SCANNER_H */
