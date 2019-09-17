#ifndef TARGETS_H
#define TARGETS_H

#include <sys/types.h>
#include <dirent.h>

#include "max.h"

/* Pids struct to handle lists of Pids*/
typedef struct {
    pid_t array[MAX_PIDS];
    size_t size;
} Pids;

/* Needles struct to handle list of needles*/
typedef struct {
    char *needles[MAX_NEEDLES]; //regex patterns
    size_t size;
} Needles;

/* Target processes struct */
typedef struct {
    char name[MAX_SHRT_NAME]; //Process name
    char source[MAX_SHRT_NAME]; // my name for proc
    Pids pids; //All Pids associated with process/service
    Needles needles; //regex patterns
} Target;

/* Init the known targets with their needles and names */
void initTargets(Target targets[MAX_TARGETS]);

/* Filter to identify /proc/ subdirs as PIDs */
static int filter(const struct dirent *dir);

/*  Get all pids associated with Targets and populate the struts */
void getTargetPids(Target targets[MAX_TARGETS]);

#ifdef DEBUG
void dumpTargets(Target *targets);
#endif

#endif
