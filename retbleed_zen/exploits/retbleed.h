// SPDX-License-Identifier: GPL-3.0-only
#include <err.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE)
#define PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
#define PROT_RW (PROT_READ | PROT_WRITE)
typedef unsigned long u64;
typedef unsigned char u8;

#define MIN(x,n) (x > n ? n : x)
#define str(s) #s
#define xstr(s) str(s)
#define NOP asm volatile("nop")
#define NOPS_str(n) ".rept " xstr(n) "\n\t"\
    "nop\n\t"\
    ".endr\n\t"
#define NOPS(n) asm volatile(NOPS_str(n))

#define map_or_die(...) do {\
    if (mmap(__VA_ARGS__) == MAP_FAILED) err(1, "mmap");\
} while(0)

static long va_to_phys(int fd, long va)
{
    unsigned long pa_with_flags;

    lseek(fd, ((long) (~0xfffUL)&va)>>9, SEEK_SET);
    read(fd, &pa_with_flags, 8);
    return pa_with_flags<<12 | (va & 0xfff);
}


/**
 * Descriptor of some memory, i.e., our reload buffer or probe buffer.
 */
struct mem_info {
    union {
        u64 va;
        u8* buf;
    };
    u64 kva;
    u64 pa;
};

static inline unsigned long get_ms() {
	static struct timeval tp;
	gettimeofday(&tp, 0);
	return tp.tv_sec * 1000 + tp.tv_usec / 1000;
}

static inline __attribute__((always_inline)) u64 rdtsc(void) {
	u64 lo, hi;
    asm volatile ("CPUID\n\t"
            "RDTSC\n\t"
            "movq %%rdx, %0\n\t"
            "movq %%rax, %1\n\t" : "=r" (hi), "=r" (lo)::
            "%rax", "%rbx", "%rcx", "%rdx");
	return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) u64 rdtscp(void) {
    u64 lo, hi;
    asm volatile("RDTSCP\n\t"
            "movq %%rdx, %0\n\t"
            "movq %%rax, %1\n\t"
            "CPUID\n\t": "=r" (hi), "=r" (lo):: "%rax",
            "%rbx", "%rcx", "%rdx");
    return (hi << 32) | lo;
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

static inline __attribute__((always_inline)) void reload_range(long base, long stride, int n, u64 *results) {
	__asm__ volatile("mfence\n");
	for (u64 k = 0; k < n; ++k) {
        u64 c = (k*13+9)&(n-1);
		unsigned volatile char *p = (u8 *)base + (stride * c);
		u64 t0 = rdtsc();
		*(volatile unsigned char *)p;
		u64 dt = rdtscp() - t0;
		//if (dt < 140) results[c]++;
		if (dt < 160) results[c]++;
	}
}
static inline __attribute__((always_inline)) void flush_range(long start, long stride, int n) {
    for (u64 k = 0; k < n; ++k) {
        volatile void *p = (u8 *)start + k * stride;
        __asm__ volatile("clflushopt (%0)\n"::"r"(p));
        __asm__ volatile("clflushopt (%0)\n"::"r"(p));
    }
}
