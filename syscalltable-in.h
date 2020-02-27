static const char *syscalltable[] = {
#ifdef __SYSCALL
#define ___SYSCALL_TMP __SYSCALL
#endif
#define __SYSCALL(x, y) [x] = #y,
#include "asm/unistd.h"
};

enum tgt_syscall_t {
#undef __SYSCALL
#define __SYSCALL(x, y) tgt_##y = x,
#include "asm/unistd.h"
};
#ifdef ___SYSCALL_TMP
#define __SYSCALL ___SYSCALL_TMP
#undef ___SYSCALL_TMP
#endif
