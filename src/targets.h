#ifndef TARGET_H
#define TARGET_H
typedef struct {
    char *processName;
    void *eggPtrAddr;
} Target;

Target targets[] = {
    {
        "gnome-keyring-daemon",
        (void*)0x6f7158,
    }
};
#endif
