#ifndef TARGET_H
#define TARGET_H
typedef struct {
    char *processName;
    void *eggPtrAddr;
    int passwdIndex;
} Target;

Target targets[] = {
    {
        "gnome-keyring-daemon",
        (void*)0x6f7158,
        4
    }
};
#endif
