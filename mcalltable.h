#ifndef _MCALLTABLE_H_
#define _MCALLTABLE_H_

#if defined(__cplusplus)
extern "C" {
#endif

static const char *mcalltable[] = {
    [0] = "mcall_set_timer",
    [1] = "mcall_console_putchar",
    [2] = "mcall_console_getchar",
    [3] = "mcall_clear_ipi",
    [4] = "mcall_send_ipi",
    [5] = "mcall_remote_fence_i",
    [6] = "mcall_remote_sfence_vma",
    [7] = "mcall_remote_sfence_vma_asid",
    [8] = "mcall_shutdown"
};

#if defined(__cplusplus)
}
#endif

#endif
