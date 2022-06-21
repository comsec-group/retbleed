#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE)
#define PROT_RW    (PROT_READ | PROT_WRITE)
#define PROT_RWX   (PROT_RW | PROT_EXEC)

#define PG_ROUND(n) (((((n)-1UL)>>12)+1)<<12)

#define str(s) #s
#define xstr(s) str(s)

#define NOP asm volatile("nop")
#define NOPS_str(n) ".rept " xstr(n) "\n\t"\
    "nop\n\t"\
    ".endr\n\t"

typedef unsigned long u64;
typedef unsigned char u8;

// start measure.
static inline __attribute__((always_inline)) u64 rdtsc(void) {
    u64 lo, hi;
    asm volatile ("CPUID\n\t"
            "RDTSC\n\t"
            "movq %%rdx, %0\n\t"
            "movq %%rax, %1\n\t" : "=r" (hi), "=r" (lo)::
            "%rax", "%rbx", "%rcx", "%rdx");
    return (hi << 32) | lo;
}

// stop meassure.
static inline __attribute__((always_inline)) u64 rdtscp(void) {
    u64 lo, hi;
    asm volatile("RDTSCP\n\t"
            "movq %%rdx, %0\n\t"
            "movq %%rax, %1\n\t"
            "CPUID\n\t": "=r" (hi), "=r" (lo):: "%rax",
            "%rbx", "%rcx", "%rdx");
    return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) void reload_range(long base, long stride, int n, u64 *results) {
    __asm__ volatile("mfence\n"); // all memory operations done.
    for (u64 k = 0; k < n; ++k) {
        u64 c = (k*17+64)&(n-1); // c=1,0,3,2
        // if (n <= 16) {
        //     u64 c = (k*7+15)&(n-1); // c=1,0,3,2 works for 16 entries Intel only
        // }
        unsigned volatile char *p = (u8 *)base + (stride * c);
        u64 t0 = rdtsc();
        *(volatile unsigned char *)p;
        u64 dt = rdtscp() - t0;
        if (dt < 70) results[c]++;
    }
}

static inline __attribute__((always_inline)) void flush_range(long start, long stride, int n) {
    asm("mfence");
    for (u64 k = 0; k < n; ++k) {
        volatile void *p = (u8 *)start + k * stride;
        __asm__ volatile("clflushopt (%0)\n"::"r"(p));
        __asm__ volatile("clflushopt (%0)\n"::"r"(p));
    }
    asm("lfence");
}

// probably not what you want for arrays. its for immediate numbers of arbitrary
// length.
static inline void mem2bin(char *dst, unsigned char *in, int l) {
    for (int i = 0; i < l; ++i) {
        dst[(l-1)-i] = (in[i>>3] >> (i&0x7) & 1) + '0';
    }
}

static inline void short2bin(char *dst, u64 in) {
    mem2bin(dst, (unsigned char*)&in, 16);
}

static inline void long2bin(char *dst, u64 in) {
    mem2bin(dst, (unsigned char *)&in, 64);
}


static u64 get_next_slow(u64 cur, int nbits) {
    while (__builtin_popcountll(++cur) != nbits)
        ;
    return cur;
}

static u64 get_next_fast(u64 cur) {
    int nbits = __builtin_popcountll(cur);
    int rbits = 0;
    for (int bi = 0; bi < 64; ++bi) {
        u64 tup = (cur>>bi)&0x3;
        if (tup == 0x3) {
            rbits ++;
        } else if (tup == 0x1) {
            // swap 0b01 -> 0b10
            cur ^= 0x3UL<<bi;
            // clear the bits cur[bi-1:0]
            cur &= ~((1UL<<bi)-1);
            // and light up the rightmost
            cur |= (1UL<<rbits)-1;
            return cur;
        }
    }
    fprintf(stderr, "get_next didnt find next\n");
    return cur;
}

// increment current pattern `cur` to next pattern which has nbits set.
static u64 get_next(u64 cur, int nbits) {
    // return get_next_slow(cur, nbits);
    if (cur == 0) {
        return (1<<nbits)-1;
    }
    if (__builtin_popcountll(cur)!=nbits) {
        return get_next_fast((1<<nbits)-1);
    }
    return get_next_fast(cur);
}

// increment current pattern `cur` to next pattern which has nbits set.
static u64 get_prev(u64 cur, int nbits) {
    while (__builtin_popcountll(--cur) != nbits)
        ;
    return cur;
}

#include <err.h>
#define MAP_OR_DIE(...) do {\
    if (mmap(__VA_ARGS__) == MAP_FAILED) err(1, "mmap");\
} while(0)

static void *
map_or_die(void *addr, u64 sz)
{
    MAP_OR_DIE(addr, sz, PROT_RW, MMAP_FLAGS, -1, 0);
    *(char*)addr=0x1; // map page.
    return addr;
}

static void *
mmap_huge(void *addr, u64 sz)
{
    MAP_OR_DIE(addr, sz, PROT_RW, MMAP_FLAGS, -1, 0);

    if (madvise(addr, 1UL<<21, MADV_HUGEPAGE) != 0) {
	    err(2, "madv %p", addr);
    }

    *(char*)addr=0x1; // map page.
    return addr;
}

static u64 rand64() {
    return (((u64)rand())<<16) ^ rand();
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

static void inline setup_segv_handler() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = &handle_segv;
    sigaction (SIGSEGV, &sa, NULL);
}
static long va_to_phys(int fd, long va)
{
    unsigned long pa_with_flags;

    lseek(fd, ((long) (~0xfffUL)&va)>>9, SEEK_SET);
    read(fd, &pa_with_flags, 8);
    return pa_with_flags<<12 | (va & 0xfff);
}

static inline unsigned long get_ms() {
	static struct timeval tp;
	gettimeofday(&tp, 0);
	return tp.tv_sec * 1000 + tp.tv_usec / 1000;
}

