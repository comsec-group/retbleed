#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <string.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>

#define ARR_SZ(a) (sizeof(a)/sizeof(a[0]))

// umask<<8 | event
#ifdef INTEL
#define PE_BA_CLEARS__ANY 0x1e6
#define PE_BR_MISP_RETIRED__ALL_BRANCHES 0xc5
#define PE_BR_MISP_RETIRED__ALL_BRANCHES_PEBS 0x4c5
#define PE_BR_MISP_RETIRED__CONDITIONAL 0x1c5
#define PE_BR_MISP_RETIRED__NEAR_CALL 0x2c5
#define PE_BR_MISP_RETIRED__NEAR_TAKEN 0x20c5
#define PE_INT_MISC__CLEAR_RESTEER_CYCLES 0x80d
#endif

struct pmu_desc {
    int nconfs;
    struct pmu_conf *pmu_confs;
};

struct pmu_conf {
    long event;
    char name[0x40];
    int fd;
    long count;
    long diff;
    // save total of everything
    long diff_sum;
    unsigned long min;
};

int perf_event_open(struct perf_event_attr *attr,
        pid_t pid, int cpu, int group_fd,
        unsigned long flags) ;
int pmu_init(struct pmu_desc *ctx);
void pmu_sample(struct pmu_desc *ctx, int end);
void pmu_print(struct pmu_desc *ctx);
