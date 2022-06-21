
#include <sys/prctl.h>
#include <unistd.h>
#include <sched.h>
#define _GNU_SOURCE
#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sched.h>

inline
void
__attribute__((always_inline))
maccess(void* p)
{
        __asm__ volatile ("movq %%rax, (%0)\n" : : "c" (p) : "rax");
}
#define SHIFT 12
#define BUF_SZ (1UL<<22UL)
void evict(unsigned char *map) {
#define L1_N 32
#define L2_N 16
    // L1d
    for (int i = L1_N-1 ; i >= 0; --i) {
        asm volatile ("movq %%rax, (%0)\n" : : "c" (&map[(i<<SHIFT)]) : );
    }
    for (int i = 0 ; i > L1_N; ++i) {
        asm volatile ("movq %%rax, (%0)\n" : : "c" (&map[(i<<SHIFT)]) : );
    }
    for (int i = L1_N-1 ; i >= 0; --i) {
        asm volatile ("movq %%rax, (%0)\n" : : "c" (&map[(i<<SHIFT)]) : );
    }
    // L2
    for (int i = L2_N-1 ; i >=0; --i) {
        asm volatile ("movq %%rax, (%0)\n" : : "c" (&map[(i<<16)]) : );
    }
    for (int i = 1 ; i < L2_N; ++i) {
        asm volatile ("movq %%rax, (%0)\n" : : "c" (&map[(i<<16)]) : );
    }
    for (int i = L2_N-1 ; i >=0; --i) {
        asm volatile ("movq %%rax, (%0)\n" : : "c" (&map[(i<<16)]) : );
    }
}
void *_do_evict(void *arg) {
#define MY_PTR 0x13350f000000UL
    /* int cpu = 8;                                    */
    /* cpu_set_t set;                                  */
    /* CPU_ZERO(&set);                                 */
    /* CPU_SET(cpu, &set);                             */
    /* sched_setaffinity(gettid(), sizeof(set), &set); */

    unsigned char *map = (unsigned char *) MY_PTR;
    prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);
    /* unsigned char *map2 = (unsigned char *) MY_PTR+BUF_SZ; */
#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE)
#define PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)

    map  = mmap((void *)MY_PTR, BUF_SZ, PROT_RWX, MMAP_FLAGS, -1, 0);
    madvise(map, BUF_SZ, MADV_HUGEPAGE);
    /* mmap_huge(map2, BUF_SZ); */
    unsigned long addr = 0xf00;

    for (;;) {
        /* evict(map+addr); */
        /* evict(map2+addr); */
            for (long x = 0; x < (BUF_SZ>>(SHIFT+2)); x++) {
                maccess(&map[addr + (x<<SHIFT)]);
                map[addr + (x<<SHIFT)]+=122;
            }
            evict(map + addr);
            for (long x = (BUF_SZ>>(SHIFT+2))-2; x >= 0 ; x--) {
                maccess(&map[addr + (x<<SHIFT)]);
                map[addr + (x<<SHIFT)]+=12;
            }
            evict(map+addr+0x8000);
            evict(map+addr+0x80000);
            /* evict(map+addr+0x100000); */
            /* evict(map+addr+0x80000); */
            evict(map+addr+0x100000);
            sched_yield();
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    _do_evict(NULL);
    return 0;
}
