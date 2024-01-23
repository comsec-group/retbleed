// SPDX-License-Identifier: GPL-3.0-only
#include "common.h"
#include <err.h>
#include <string.h>
#include <stdlib.h>

// how many rounds to try mispredict? Many rounds often breaks things. Probably
// there's some usefulness bits that downvotes a bad prediction.
#define ROUNDS 10

// RB, reload buffer
#define RB_PTR 0x13370000
#define RB_STRIDE_BITS 12
#define RB_SLOTS 0x10

// this is the slot of the reload buffer we will light up when we have
// misprediction.
#define SECRET 9

// try all user-space patterns
#define MAX_BIT 47

// use some random branches leading up to the mispredicting branch. Seems to be
// very effective but not required. For Zen3 this is required, IIRC.
/* #define USE_RANDOM */

// How many branches to execute before training / mispredicting? More seems to
// help but again, not required.
#define RET_PATH_LENGTH 33

// When training
#define TRAIN_PATH   0x2000000000UL

// This is where we will place the branch that we will use for training. When
// mispredicting, the BPU uses the branch resolution feedback from this branch.
#define BR_SRC1    0x41bababababfUL

// flip at most this many bits in the victim src address.
#define MAX_MUTATIONS 3

// skip flipping bits in the lower part of training src, we can often assume that
// they have to match with the lower bits
#define SKIP_LOWER_BITS 0

__attribute__((aligned(4096))) static u64 results[RB_SLOTS] = {0};

// discloure gadget. leak content or "rdi", which is number 0 -- RB_SLOTS
void train_dst();
asm(
    ".align 0x2000\n\t"
    "train_dst:\n\t"
    "shl $" xstr(RB_STRIDE_BITS) ", %rdi\n\t"
    "mov "xstr(RB_PTR) "(%rdi), %rax\n\t"
    "lfence\n\t" // stop here when speculating ;)
    "jmp flush\n\t"
);

// spec_dst is the real path. we want to land at train_dst instead of here to
// have a successful misprediction.
void spec_dst();
asm(
    "spec_dst:\n\t"
    "lfence\n\t" // stop here when speculating ;)
    "jmp reload\n\t"
);

/**
 * calling this "template" because it is never executed. We are copying the
 * instructions to BR_SRC1.
 */
void br_src_training_tmpl();
void br_src_training_tmpl_end();
asm(
    ".align 0x80000\n\t"
    "br_src_training_tmpl:\n\t"
    NOPS_str(0x20)
    "jmp *%r8\n\t" //
    "br_src_training_tmpl_end:\n\t"
);

/**
 * calling this "template" because it is never executed. We are copying the
 * instructions to different locations with intention of causing a collision
 * with BR_SRC1.
 */
#define USE_RET
void br_src_mispredict_tmpl();
void br_src_mispredict_tmpl_end();
asm(
    ".align 0x80000\n\t"
    "br_src_mispredict_tmpl:\n\t"
    NOPS_str(0x20)
#ifdef USE_RET
    "push %r8\n\t"
    "ret\n\t"
#else
    NOPS_str(1)
    "jmp *%r8\n\t"
#endif
    "br_src_mispredict_tmpl_end:\n\t"
);

int main(int argc, char *argv[])
{
    int br_src_training_sz = br_src_training_tmpl_end-br_src_training_tmpl;
    int br_src_mispredict_sz = br_src_mispredict_tmpl_end-br_src_mispredict_tmpl;
    // reload buffer. We will check for cache hits in rb[SECRET<<RB_STRIDE_BITS]
    map_or_die((void*)RB_PTR, (RB_SLOTS<<RB_STRIDE_BITS) + 0x1000, PROT_RW, MMAP_FLAGS, -1, 0);

    // unless we compile with USE_RANDOM, both speculation and training paths
    // (i.e., paths until the targeted branch) will be the same.
    u64 training_path[RET_PATH_LENGTH];
    u64 speculation_path[RET_PATH_LENGTH];

    // Do execute some history to get collisions more consistently. Nvertheless,
    // as we've stated in the paper and as we see in the exploits, it does not
    // seem to be needed always.
    map_or_die((void*)(TRAIN_PATH&~0xfff), 0x1000, PROT_RWX, MMAP_FLAGS, -1, 0);

    // this is where we place the "victim" branch that we will try to induce
    // collisions on.
    map_or_die((void*)(BR_SRC1 & ~0xfff), PG_ROUND((BR_SRC1&0xfff) +
                br_src_training_sz), PROT_RWX, MMAP_FLAGS, -1, 0);

    memcpy((void *)BR_SRC1, br_src_training_tmpl, br_src_training_sz);

    // we train by ROP-ing. we just push a bunch of TRAIN_PATH to the stack and
    // then execute a RET.
    for (int ii = 0; ii < RET_PATH_LENGTH; ++ii) {
        training_path[ii] = TRAIN_PATH;
#ifndef USE_RANDOM
        // when we USE_RANDOM we will change is every single round. That way we
        // know there's no history-backed (TAGE) prediction possible.
        speculation_path[ii] = TRAIN_PATH;
#endif
    }
    *(u8*)TRAIN_PATH = 0xc3; // ret

    flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);
    printf("[.] The following format is used\n");
    printf("[.] BITS_FLIPPED; c=RB_ENTRY; BR_SRC1; MISPREDICTING_BRANCH; SIGNAL\n");
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
            memset(results, 0, RB_SLOTS*sizeof(results[0]));
            ptrn = get_next(ptrn, nbits);
            ptrn_shl = ptrn<<SKIP_LOWER_BITS;
            u64 br_src_mispredict = BR_SRC1 ^ ptrn_shl;
            u64 br_src_mispredict_map_sz = PG_ROUND((br_src_mispredict&0xfff) +
                    br_src_mispredict_sz);
            if (mmap((void*)(br_src_mispredict & ~0xfff),
                        br_src_mispredict_map_sz, PROT_RWX, MMAP_FLAGS, -1, 0)
                    == MAP_FAILED) {
                // not able to map here.. maybe occupied. try some other
                // mutation instead.
                continue;
            }
            // write our mispredicting branch
            memcpy((u8 *)br_src_mispredict, br_src_mispredict_tmpl, br_src_mispredict_sz);

            for (int i = 0; i<ROUNDS; ++i) {
#ifdef USE_RANDOM
                for (int ii = 0; ii < RET_PATH_LENGTH; ++ii) {
                    speculation_path[ii] = rand64();
                    if (mmap((void*)(speculation_path[ii] & ~0xfff), 0x1000, PROT_RWX, MMAP_FLAGS, -1, 0) == MAP_FAILED) {
                        // sometimes we get an occupied address, so try again or
                        // otherwise just die.
                        speculation_path[ii] = rand64();
                        map_or_die((void*)(speculation_path[ii] & ~0xfff), 0x1000, PROT_RWX, MMAP_FLAGS, -1, 0);
                    }
                    *(u8*)(speculation_path[ii]) = 0xc3; // ret
                }
#endif
                asm(
                        "lfence\n\t"
                        "mov %0, %%r8\n\t"
                        "mov $0x2, %%rdi\n\t" // doesn't matter
                        "pushq %[br_src]\n\t"
                        "mov %[retp], %%r10 \n\t"
                        // build an execution path to prime some history
                        ".rept " xstr(RET_PATH_LENGTH) "\n\t"
                        "pushq (%%r10)\n\t"
                        "add $8, %%r10\n\t"
                        ".endr\n\t"
                        "ret\n\t"
                        :: "r"(train_dst), [retp]"r"(training_path), [br_src]"r"(BR_SRC1) : "rax", "rdi", "r8", "r9", "r10"
                   );
                // come back here after training.
                asm("flush:");

                flush_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS);
                asm(
                        "mov %0, %%r8\n\t"
                        "mov $" xstr(SECRET) ", %%rdi\n\t"
                        "pushq %[br_src]\n\t"
                        "mov %[retp], %%r10 \n\t"
                        // build an execution path to prime some history
                        ".rept " xstr(RET_PATH_LENGTH) "\n\t"
                        "pushq (%%r10)\n\t"
                        "add $8, %%r10\n\t"
                        ".endr\n\t"
                        "ret\n\t"
                        :: "r"(spec_dst), [retp]"r"(speculation_path), [br_src]"r"(br_src_mispredict): "rax", "rdi", "r8", "r9", "r10"
                   );
                printf("round\n");
                // come back  from spec_dst here.
                asm("reload:");
                reload_range(RB_PTR, 1<<RB_STRIDE_BITS, RB_SLOTS, results);
#ifdef USE_RANDOM
                for (int ii = 0; ii < RET_PATH_LENGTH; ++ii) {
                    munmap((void*)(speculation_path[ii]&~0xfff), 0x1000);
                }
#endif
            }
            for (int i = 0 ; i < RB_SLOTS; ++i) {
                // lets print everything if there's a hit
               if (results[i] > 1) {
                   char binstr[64+1] = {0}; //0,1 or null
                    mem2bin(binstr, (unsigned char*)&ptrn_shl, 48);
                    printf("[+] %s; c=%02d; 0x%012lx; 0x%012lx; %0.2f", binstr,
                            i, (u64)(BR_SRC1 + br_src_training_sz-1),
                            (u64)(br_src_mispredict+br_src_mispredict_sz-1),
                            results[i]/(ROUNDS+.0));
                   printf("\n");
               }
            }
            memset(results, 0, RB_SLOTS*sizeof(results[0]));
            munmap((void*)(br_src_mispredict&~0xfffUL), br_src_mispredict_map_sz);
        }
    }
    return 0;
}
