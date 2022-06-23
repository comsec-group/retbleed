#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

char mem_info[0x800];
#define PROT_RW (PROT_READ | PROT_WRITE)
#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE)

unsigned long get_anon_huge(int fd) {
    pread(fd, mem_info, sizeof(mem_info), 0);
    return atoi(&strstr(mem_info, "AnonHugePages:")[sizeof("AnonHugePages: ")]);
}

unsigned long get_free_mem_kb(int fd) {
    pread(fd, mem_info, sizeof(mem_info), 0);
    return atoi(&strstr(mem_info, "MemFree:")[sizeof("MemFree: ")]);
}

unsigned long get_free_swap_kb(int fd) {
    pread(fd, mem_info, sizeof(mem_info), 0);
    return atoi(&strstr(mem_info, "SwapFree:")[sizeof("SwapFree: ")]);
}

unsigned long get_avail_kb(int fd) {
    pread(fd, mem_info, sizeof(mem_info), 0);
    return atoi(&strstr(mem_info,"MemAvailable:")[sizeof("MemAvailable: ")]);
}


#define map_or_die(...) do {\
    if (mmap(__VA_ARGS__) == MAP_FAILED) err(1, "mmap");\
} while(0)

#define ROUND_UP_GB(x) (((((x)-1) >> 30) + 1) << 30)
#define ROUND_DN_GB(x) (((x) >> 30) << 30)

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);
    char *giga_range =(void *)0x44000000000UL;
    char *mega_range =(void *)0x20000000000UL;

    int pm_fd = open("/proc/self/pagemap", O_RDONLY);
    int mi_fd = open("/proc/meminfo", O_RDONLY);

    unsigned long freemem_kb = get_free_mem_kb(mi_fd);
    unsigned long SZ = freemem_kb << 10;

    map_or_die(
            giga_range,
            SZ,
            PROT_RW,
            (MAP_NORESERVE|MMAP_FLAGS)&~MAP_POPULATE, -1, 0);

    madvise(giga_range, SZ, MADV_HUGEPAGE);
    printf("Allocate %lu GB...\n", SZ>>30);
    for (unsigned long a = 0; a < SZ; a += 1<<21) {
        *(unsigned long *)&giga_range[a] = rand();
    }
    printf("%ld MiB remains. Fill with small pages\n", get_free_mem_kb(mi_fd)>>10);
    map_or_die(mega_range, SZ, PROT_RW, (MAP_NORESERVE|MMAP_FLAGS)&~MAP_POPULATE, -1, 0);
    long a;
    for (a = 0; a < SZ; a += 0x1000) {
	    mega_range[a] = a;
    }
    return 0;
}
