#ifndef TARGETS_H
#define TARGETS_H

#include <sys/types.h>

#define MAX_PIDS 24
#define MAX_NAME_SIZE 128
#define MAX_TARGETS 4
#define MAX_NEEDLES 4
#define MAX_SOURCE_SIZE 32

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
    char name[MAX_NAME_SIZE]; //Process name
    char source[MAX_SOURCE_SIZE];
    Pids pids; //All Pids associated with process/service
    Needles needles; //regex patterns
} Target;

/* Init the known targets with their needles and names */
void initTargets(Target targets[MAX_TARGETS]);

#endif
