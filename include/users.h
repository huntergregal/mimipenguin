#ifndef USERS_H
#define USERS_H

#include <sys/types.h>

struct User {
    char *uname;
    size_t uname_len;
    char *id_salt;
    size_t id_salt_len;
    char *hash;
    size_t hash_len;
};

typedef struct User user_t;

// Populates an array of User structs with local
// users and their hashes/salts. Only targets
// users with a valid hash
// -1 = error,
// 0 = no valid users (prob an error)
// number of valid users = success
int GetUsers(user_t **users);

// Frees list of users
void PutUsers(user_t **users, int nusers);

// Check for a match of hashed version of str against user hashes
// If match return user index
// else 0 for no match
int CheckForUserHash(user_t *users, int nusers, char *str);

#endif
