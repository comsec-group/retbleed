// SPDX-License-Identifier: GPL-3.0-only
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>

/**
 * Pseudocode
 *
 */

#define INTEL
#include "pmu.h"

#include "sys/mman.h"
#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE)
#define ARR_SZ(a) (sizeof(a)/sizeof(a[0]))
#define PROT_RW    (PROT_READ | PROT_WRITE)
#define PROT_RWX   (PROT_RW | PROT_EXEC)

#define PG_ROUND(n) (((((n)-1UL)>>12)+1)<<12)

#define str(s) #s
#define xstr(s) str(s)

#define X_MAX 128
void* ret_path[X_MAX+1] = {};

void ret_place();
asm("ret_place: ret");

// we copy this to all random locations.
typedef void (*path_step_fn)(int d, void *path);
void path_step(int d, void *path);
void path_step__end();
asm("path_step:\n\t"
        "test %rdi, %rdi\n\t"
        "jz .END\n\t"
            "dec %rdi\n\t"
            "add $8, %rsi\n\t"
            "call *(%rsi)\n\t"
        ".END:\n\t"
        "lfence\n\t"

#ifdef USE_JMP
        "pop %rax\n\t"
        "jmp *%rax\n\t"
#else
        "ret\n\t"
#endif
        "path_step__end: ");

void recurse(int d);
asm("recurse:\n\t"
        "test %rdi, %rdi\n\t"
        "jz end\n\t"
        "dec %rdi\n\t"
        "call recurse\n\t"
        "end: ret");

int main(int argc, char *argv[])
{
    struct pmu_conf pmu_confs[] = {
#ifdef INTEL
        // INTEL
        { PE_BR_MISP_RETIRED__CONDITIONAL, "br_misp_retired.conditional" },
        { PE_BR_MISP_RETIRED__NEAR_CALL, "br_misp_retired.near_call" },
        { PE_BR_MISP_RETIRED__NEAR_TAKEN, "br_misp_retired.near_taken" },
#else
        // AMD
        { 0xc9,   "ex_ret_near_ret_mispred"},
#endif
    };

    struct pmu_desc pmu_ctx = {
        .nconfs = sizeof(pmu_confs) / sizeof(pmu_confs[0]),
        .pmu_confs = pmu_confs
    };

    if (pmu_init(&pmu_ctx) != 0) {
        err(1, "pmu");
    }
    if (argc != 2) {
        fprintf(stderr, "usage: %s <x>\n", argv[0]);
        exit(1);
    }
    int x = atoi(argv[1]);
    if (x > X_MAX || x < 0) {
        fprintf(stderr, "x: must be an integer, 0-%d, here: %d\n", X_MAX, x);
        exit(1);
    }
    memset(ret_path, 0, sizeof(ret_path));

    for (int i = 0; i < x; ++i) {
        ret_path[i] = ret_place;
    }
    srand(getpid());
#define ROUNDS 4000
    for(int i = 0; i < ROUNDS; ++i) {
        for (int ii = 0 ; ii < x; ++ii) {
            ret_path[ii] = (void *)((((unsigned long)rand())<<16) ^ rand());
            // mind the page boundary.
            if (mmap((void*)((long)ret_path[ii] & ~0xfff), 0x2000, PROT_RWX, MMAP_FLAGS, -1, 0) == MAP_FAILED) {
                ret_path[ii] = (void *)((((unsigned long)rand())<<16) ^ rand());
                if (mmap((void*)((long)ret_path[ii] & ~0xfff), 0x2000, PROT_RWX, MMAP_FLAGS, -1, 0) == MAP_FAILED) {
                    err(2, "mmap");
                }
            }
            //printf("ret_path[%d] = %lx\n", ii, ret_path[ii]);
            memcpy(ret_path[ii], path_step, path_step__end - path_step);
        }
        #define cpuid asm volatile("cpuid" ::: "eax", "ebx","ecx","edx")
        pmu_sample(&pmu_ctx, 0);
        cpuid;
        /* recurse(x); */
        if (x>0) ((path_step_fn)ret_path[0])(x-1, ret_path);
        /* asm("ret"); */
        /* printf("never here\n"); */
        /* asm("finish:"); */
        cpuid;
        pmu_sample(&pmu_ctx, 1);

        for (int ii = 0 ; ii < x; ++ii) {
            munmap((void *)((long)ret_path[ii] & ~0xfff), 0x2000);
        }
    }

    for (int i = 0; i < pmu_ctx.nconfs; ++i) {
       fprintf(stderr, "%s;%lu\n", pmu_ctx.pmu_confs[i].name, pmu_ctx.pmu_confs[i].min);
    }


    // INTEL
#ifdef INTEL
    // sampling many perf counters is inaccurate. Sometimes there are more misp.
    // calls and conditionals than there are misp taken branches. Could also be
    // that a mispredicted non-taken conditional will count as a misp.cond but
    // not as a misp taken branch.
#define MAX(a,b) ((a) > (b) ? a : b)
    printf("%d\n", MAX(0, (int)pmu_ctx.pmu_confs[2].min - (int)pmu_ctx.pmu_confs[0].min - (int)pmu_ctx.pmu_confs[1].min));
#else
    // AMD
    printf("%lu\n", pmu_ctx.pmu_confs[0].min);
#endif
    return 0;
}
