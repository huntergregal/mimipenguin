#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <crypt.h>
#include <stdio.h>

#include "dbg.h"
#include "users.h"
#include "max.h"

// Does user from shadow line have a hash?
int isValidUser(char *line)
{
    char *cur = NULL;

    if ( (cur = strchr(line, ':')) == NULL )
    {
        log_warn("Invalid user line?!");
        return -1;
    }
    if ( cur[1] == '$' ) //valid user with a hash
        return 1;
    else
        return 0; // invalid user, probably disabled or locked
}

int CountUsers(FILE *fp)
{
    char line[MAX_USER_LINE] = {0};
    int cnt = 0;

    while ( fgets(line, MAX_USER_LINE-1, fp) )
    {
        switch ( isValidUser(line) )
        {
            case -1:
                log_warn("Invalid user line?");
                break;
            case 0: // not valid aka no hash
                break;
            default: //valid
                cnt++;
                break;
        }
    }
    return cnt;
}
// populate our user list with hashes, salts, and names
int PopulateUsers(FILE *fp, user_t *users, int nusers)
{
    char line[MAX_USER_LINE] = {0};
    int cur = 0;
    char *uname = NULL;
    char *id_salt_hash = NULL;
    char *id_salt = NULL, *id_salt_end = NULL;
    int id_salt_len = 0;
    char *hash = NULL;
    
    while ( fgets(line, MAX_USER_LINE-1, fp) )
    {
        if ( cur >= nusers )
        {
            log_error("More users found the before?!");
            return -1; //FATAL
        }

        if ( (uname = strtok(line, ":")) == NULL )
        {
            log_warn("invalid user line?");
            continue;
        }
        if ( uname[strlen(uname)+1] != '$' )
        {
            //debug("%s", &uname[strlen(uname)+1]);
            //log_warn("Invalid user, no hash [%s]", uname);
            continue;
        }
        if ( (id_salt_hash = strtok(NULL, ":")) == NULL )
        {
            log_warn("Corrupted user line?");
            continue;
        }
        // extract hash after id_salt
        if ( (id_salt_end = strrchr(id_salt_hash, '$')) == NULL )
        {
            log_warn("Corrupted user line? No salt end?");
            continue;
        }
        hash = id_salt_end+1;
        id_salt_len = hash - id_salt_hash;

        // allocate memory for the fields and populate
        users[cur].uname_len = strlen(uname) + 1; 
        if ( (users[cur].uname = calloc(users[cur].uname_len, 1)) == NULL )
        {
            log_error("Failed to calloc uname");
            return -1; //FATAL
        }
        memcpy(users[cur].uname, uname, users[cur].uname_len-1);

        users[cur].id_salt_len = id_salt_len + 1;
        if ( (users[cur].id_salt = calloc(users[cur].id_salt_len, 1)) == NULL )
        {
            log_error("Failed to calloc id_salt");
            return -1; //FATAL
        }
        memcpy(users[cur].id_salt, id_salt_hash, users[cur].id_salt_len-1);

        users[cur].hash_len = strlen(hash) + 1;
        if ( (users[cur].hash = calloc(users[cur].hash_len, 1)) == NULL )
        {
            log_error("Failed to calloc hash");
            return -1; //FATAL
        }
        memcpy(users[cur].hash, hash, users[cur].hash_len-1);
        debug("valid users found: %s", uname);
        cur++; //next user
    }

    if ( cur != (nusers) )
    {
        log_error("User count mismatch! %d vs %d", cur, nusers);
        return -1; //FATAL
    }
}

// Populates an array of User structs with local
// users and their hashes/salts. Only targets
// users with a valid hash
// -1 = error,
// 0 = no valid users (prob an error)
// number of valid users = success
int GetUsers(user_t **users)
{
    FILE *fp = NULL;
    int num_users = 0;
    int ret = -1;
    char line[MAX_USER_LINE] = {0};

    if ( (fp = fopen("/etc/shadow", "r")) == NULL )
    {
        log_error("Failed to open /etc/shadow");
        goto DONE;
    }

    // first count valid users
    if ( (num_users = CountUsers(fp)) == 0)
    {
        log_warn("No valid users on system?");
        goto DONE;
    }

    log_info("Found %d valid users on system", num_users);

    // allocate space for our valid user list
    if ( (*users = (user_t*)calloc(num_users, sizeof(user_t))) == NULL )
    {
        log_error("Failed to calloc user_t list");
        goto DONE;
    }

    rewind(fp); //reset fp pos

    if ( PopulateUsers(fp, *users, num_users) < 0 )
    {
        log_error("Fatal error populating the users");
        goto DONE;
    }

    ret = num_users;
    DONE:
        if ( fp != NULL )
            fclose(fp);
        return ret;
}


// Frees all memory being used by the User list
void PutUsers(user_t **users, int nusers)
{
    int i = 0;
    if ( *users == NULL )
        return;
    for ( i = 0; i < nusers; i++ )
    {
        if ( (*users)[i].uname != NULL )
            (*users)[i].uname = NULL;
        if ( (*users)[i].id_salt != NULL )
            free((*users)[i].id_salt);
        if ( (*users)[i].hash != NULL )
            free((*users)[i].hash);
    }
    free(*users);
    *users = NULL;
}

// Check for a match of hashed version of str against user hashes
// If match return user index
// else 0 for no match
int CheckForUserHash(user_t *users, int nusers, char *str)
{
    int i = 0;
    char *str_hash = NULL;

    for ( i = 0; i < nusers; i++ )
    {
        if ( (str_hash = crypt((const char*)str, users[i].id_salt)) == NULL )
        {
            log_error("crypt failed string: %s, salt: %s", str, users[i].id_salt);
            continue;
        }
        if ( strstr(str_hash, users[i].hash) != NULL )
        {
            printf("%s : %s\n", users[i].uname, str);
            return 1; // FOUND PASS!
        }
    }
    return 0; // not found
}
