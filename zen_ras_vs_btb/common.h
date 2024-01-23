// SPDX-License-Identifier: GPL-3.0-only
#include <stdio.h>
#include <err.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE)
#define PROT_RW    (PROT_READ | PROT_WRITE)
#define PROT_RWX   (PROT_RW | PROT_EXEC)

#define PG_ROUND(n) (((((n)-1UL)>>12)+1)<<12)

#define str(s) #s
#define xstr(s) str(s)

#define NOP asm volatile("nop")
#define NOPS_str(n) ".rept " xstr(n) "\n\t"\
    "nop\n\t"\
    ".endr\n\t"

/*                         6690 NOP2_OVERRIDE_NOP */
/*                       0f1f00 NOP3_OVERRIDE_NOP */
/*                     0f1f4000 NOP4_OVERRIDE_NOP */
/*                   0f1f440000 NOP5_OVERRIDE_NOP */
/*                 660f1f440000 NOP6_OVERRIDE_NOP */
/*               0f1f8000000000 NOP7_OVERRIDE_NOP */
/*             0f1f840000000000 NOP8_OVERRIDE_NOP */
/*           660f1f840000000000 NOP9_OVERRIDE_NOP */
/*         66660f1f840000000000 NOP10_OVERRIDE_NOP */
/*       6666660f1f840000000000 NOP11_OVERRIDE_NOP */
/*     666666660f1f840000000000 NOP12_OVERRIDE_NOP */
/*   66666666660f1f840000000000 NOP13_OVERRIDE_NOP */
/* 6666666666660f1f840000000000 NOP14_OVERRIDE_NOP */
/* 666666666666660f1f840000000000 */

//https://developer.amd.com/wordpress/media/2013/12/55723_SOG_Fam_17h_Processors_3.00.pdf
//p. 26
#define NOP2  ".byte 0x66,0x90\n\t"
#define NOP3  ".byte 0x0f,0x1f,0x00\n\t"
#define NOP4  ".byte 0x0f,0x1f,0x40,0x00\n\t"
#define NOP5  ".byte 0x0f,0x1f,0x44,0x00,0x00\n\t"
#define NOP6  ".byte 0x66,0x0f,0x1f,0x44,0x00,0x00\n\t"
#define NOP13 ".byte 0x66,0x66,0x66,0x66,0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00\n\t"
#define NOP14 ".byte 0x66,0x66,0x66,0x66,0x66,0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00\n\t"
#define NOP15 ".byte 0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00\n\t"

#define NOPS(n) asm volatile(NOPS_str(n))

#define ARR_SZ(a) (sizeof(a)/sizeof(a[0]))

// thanks, Jann Horn.
#define CRAPPY_BHB_RANDOMIZE \
    asm volatile(              \
            "test $0x1, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x2, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x4, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x8, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x10, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x20, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x40, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x80, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x100, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x200, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x400, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x800, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x1000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x2000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x4000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x8000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x10000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x20000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x40000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x80000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x100000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x200000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x400000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x800000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x1000000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x2000000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x4000000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            "test $0x8000000, %[foo]\n\tjz 1f\n\tnop\n\t1:\n\t" \
            :/*out*/                            \
            :/*in*/                             \
            [foo] "r"((unsigned int)random()) \
            :/*clobber*/                        \
            "cc","memory"                     \
            );


typedef unsigned long u64;
typedef unsigned char u8;

// because I always forget how to cast.
typedef void (*fp)();

// pipeline_flush
#define cpuid asm volatile("cpuid" ::: "eax", "ebx","ecx","edx")

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

static inline __attribute__((always_inline)) void reload_one(long addr, u64 *results) {
    unsigned volatile char *p = (u8 *)addr;
    u64 t0 = rdtsc();
    *(volatile unsigned char *)p;
    u64 dt = rdtscp() - t0;
    if (dt < 40) results[0]++;
}

// static inline __attribute__((always_inline)) void reload_range(long base, long stride, int n, u64 *results) {
//     __asm__ volatile("mfence\n"); // all memory operations done.
//     for (u64 k = 0; k < n; ++k) {
//         u64 c = (k*13+9)&(n-1);
//         unsigned volatile char *p = (u8 *)base + (stride * c);
//         u64 t0 = rdtsc();
//         *(volatile unsigned char *)p;
//         u64 dt = rdtscp() - t0;
//         if (dt < 130) results[c]++;
//     }
// }

// this one is better because it doesn't prefect on rocket and alder
static inline __attribute__((always_inline)) void reload_range(long base, long stride, int n, u64 *results) {
    __asm__ volatile("mfence\n"); // all memory operations done.
    for (u64 k = 0; k < n/4; ++k) {
        //u64 c = (k*7+15)&(n-1); // c=1,0,3,2 works for 16 entries Intel only
        u64 c = (k*7+35)&(n-1); // c=1,0,3,2
        unsigned volatile char *p = (u8 *)base + (stride * c);
        u64 t0 = rdtsc();
        *(volatile unsigned char *)p;
        u64 dt = rdtscp() - t0;
        if (dt < 130) results[c]++;
    }
    for (u64 k = n/4 ; k < n/2; ++k) {
        u64 c = (k*7+35)&(n-1); // c=1,0,3,2
        unsigned volatile char *p = (u8 *)base + (stride * c);
        u64 t0 = rdtsc();
        *(volatile unsigned char *)p;
        u64 dt = rdtscp() - t0;
        if (dt < 130) results[c]++;
    }
    for (u64 k = n/2 ; k < n/2 + (n/4); ++k) {
        u64 c = (k*7+35)&(n-1); // c=1,0,3,2
        unsigned volatile char *p = (u8 *)base + (stride * c);
        u64 t0 = rdtsc();
        *(volatile unsigned char *)p;
        u64 dt = rdtscp() - t0;
        if (dt < 130) results[c]++;
    }
    for (u64 k = n/2+(n/4) ; k < n; ++k) {
        u64 c = (k*7+35)&(n-1); // c=1,0,3,2
        unsigned volatile char *p = (u8 *)base + (stride * c);
        u64 t0 = rdtsc();
        *(volatile unsigned char *)p;
        u64 dt = rdtscp() - t0;
        if (dt < 130) results[c]++;
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
    // __asm__ volatile("clflush (%0)\n"::"r"(start+16*stride));
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

static long va_to_phys(int fd, long va)
{
    unsigned long pa_with_flags;

    lseek(fd, ((long) va)>>9, SEEK_SET);
    read(fd, &pa_with_flags, 8);
    // printf("phys %p\n", (void*)pa_with_flags);
    return pa_with_flags<<12 | (va & 0xfff);
}

#define COLOR_NC            "\033[0m"
#define COLOR_BG_RED        "\033[41m"
#define COLOR_BG_PRED       "\033[101m"
#define COLOR_BG_GRN        "\033[42m"
#define COLOR_BG_PGRN       "\033[102m"
#define COLOR_BG_YEL        "\033[43m"
#define COLOR_BG_PYEL       "\033[103m"
#define COLOR_BG_BLU        "\033[44m"
#define COLOR_BG_PBLU       "\033[104m"
#define COLOR_BG_MAG        "\033[45m"
#define COLOR_BG_PMAG       "\033[105m"
#define COLOR_BG_CYN        "\033[46m"
#define COLOR_BG_PCYN       "\033[106m"
#define COLOR_BG_WHT        "\033[47m"
#define COLOR_BG_PWHT       "\033[107m"

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

static inline __attribute__((always_inline))
void print_results(u64 *results, int n) {
    for (int i = 0; i < n; ++i) {
        printf("%lu ", results[i]);
    }
    puts("");
}

#define ASM_JMP_RAX "\xff\xe0"
#define ASM_JMP_RSI "\xff\xe6"
#define ASM_JMP_RDI  "\xff\xe7"
#define ASM_CALL_RDI "\xff\xd7"
