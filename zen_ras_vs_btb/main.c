#include <stdio.h>
#include "common.h"
#include <string.h>

#define BTI_PATTERN 0b000000000000001000000000001000000000000000000000;
#define RB_SLOTS 16
#define RB_SHIFT 12
#define PG_ROUND(n) (((((n)-1UL)>>12)+1)<<12)

void RAS_gadget(char*, char*);
asm(
        ".align 0x40        \n\t"
        "RAS_gadget:        \n\t"
        "call A             \n\t"
        "prefetcht0 (%rdi)  \n\t" // emit RAS signal
        "add $0x10000, %rsi \n\t" // remove BTI signal
        "add $0x10000, %rdi \n\t" // remove RAS signal
        "int3               \n\t" // stop speculation
);

void A();
asm(
        ".align 0x40  \n\t"
        ".rept 0x3a   \n\t" // pad to place the BB start on one CL
        "  nop        \n\t" // and ends on the preceding CL.
        ".endr        \n\t"
        "A:           \n\t"
        "mfence       \n\t" // Get reliable signal for both RAS and BTI
        "add $8, %rsp \n\t" // skip return target
        "ret          \n\t" // go
        "A__end:      \n\t");
void A__end();

void C();
asm(
        "C:                 \n\t"
        "prefetcht0 (%rsi)  \n\t" // emit BTI signal
        "add $0x10000, %rsi \n\t" // remove BTI signal
        "add $0x10000, %rdi \n\t" // remove RAS signal
        "mfence             \n\t" // stop speculation
        "ret                \n\t");

__attribute__((aligned(0x1000))) char rb[RB_SLOTS<<RB_SHIFT];

unsigned long hist[RB_SLOTS];

int main(int argc, char *argv[])
{
    for (int i = 0 ; i < RB_SLOTS ; ++i) {
        // make sure they are all mapped
        rb[i<<RB_SHIFT] = i;
    }
    memset(hist, 0, 8*RB_SLOTS);

    int BTI_gadget_sz = A__end - A;
    long BTI_gadget = (long)A ^ BTI_PATTERN;
    printf("Collision block @ %lx--%lx\n", BTI_gadget, BTI_gadget+BTI_gadget_sz);

    typedef void (*fn)();
    MAP_OR_DIE((void *)(BTI_gadget & ~0xfff), PG_ROUND((BTI_gadget&0xfff) +
                BTI_gadget_sz), PROT_RWX, MMAP_FLAGS, -1, 0);
    memset((void *)BTI_gadget, 0x90, BTI_gadget_sz);


/* #define RET_TRAIN // this option will not work, returns don't update the BTB */
#ifdef RET_TRAIN
    memcpy((void *)(BTI_gadget + BTI_gadget_sz - 2), "\x50\xc3", 2);
#else
    memcpy((void *)(BTI_gadget + BTI_gadget_sz - 2), ASM_JMP_RDI, sizeof(ASM_JMP_RDI) - 1);
#endif

    flush_range((long)rb, 1<<RB_SHIFT, RB_SLOTS);

    RAS_gadget(rb+0x5000, NULL);
    reload_range((long)rb, 1<<RB_SHIFT, RB_SLOTS, hist);
    print_results(hist, RB_SLOTS);

    // train with 5 active
#ifdef RET_TRAIN
    asm(
            "mov %2, %%rsi\n\t"
            "mov %1, %%rax\n\t"
            "call *%0\n\t"
            :: "r"((void *)BTI_gadget), "r"(C), "r" (rb+0x4000) : "rsi", "rax");
#else
    ((fn)BTI_gadget)(C, rb+0x4000);
#endif
    memset(hist, 0, 8*RB_SLOTS);
    flush_range((long)rb, 1<<RB_SHIFT, RB_SLOTS);

    RAS_gadget(rb + 0x4000, rb+0x8000);
    reload_range((long)rb, 1<<RB_SHIFT, RB_SLOTS, hist);
    print_results(hist, RB_SLOTS);

    return 0;
}
