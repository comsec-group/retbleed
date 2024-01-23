// SPDX-License-Identifier: GPL-3.0-only
#include "pmu.h"

inline int perf_event_open(struct perf_event_attr *attr,
        pid_t pid, int cpu, int group_fd,
        unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

__attribute__((always_inline))
inline int pmu_init (struct pmu_desc *ctx) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    struct pmu_conf *pmu_confs = ctx->pmu_confs;
    for (int i = 0; i < ctx->nconfs; ++i) {
        pe.config = pmu_confs[i].event;
#ifndef PERF_ATTR_SIZE_VER6
#define PERF_ATTR_SIZE_VER6 120
#endif

        pe.size = PERF_ATTR_SIZE_VER5;
        pe.type = PERF_TYPE_RAW;
        pe.sample_type = PERF_SAMPLE_CPU | PERF_SAMPLE_RAW;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;
        pe.exclude_guest = 1;
        pe.exclude_idle = 1;
        pe.exclude_callchain_kernel = 1;
        /* pe.sample_freq = 0xffffffffffffffff; */
        /* pe.freq = 0; */
        /* pe.sample_period=10000000; */
        /* pe.disabled = 1; enable later with via ioctl syscall */
        /* pe.sample_type = PERF_FORMAT_TOTAL_TIME_ENABLED|PERF_FORMAT_TOTAL_TIME_RUNNING; */
        pmu_confs[i].fd = perf_event_open(&pe, 0, -1, -1, PERF_FLAG_FD_NO_GROUP);
        if (pmu_confs[i].fd == -1) {
            return -1;
        }
        pmu_confs[i].min = -1UL;
    }
    return 0;
}

__attribute__((always_inline))
inline void pmu_sample (struct pmu_desc *ctx, int end) {
    long newcount;
    struct pmu_conf *pmu_confs = ctx->pmu_confs;
    for (int i = 0; i < ctx->nconfs; ++i) {
        read(pmu_confs[i].fd, &newcount, 8);
        if (end) {
            pmu_confs[i].diff = newcount - pmu_confs[i].count;
            pmu_confs[i].diff_sum += pmu_confs[i].diff;
            if (pmu_confs[i].diff < pmu_confs[i].min)  {
                pmu_confs[i].min = pmu_confs[i].diff;
            }
        } else {
            pmu_confs[i].count = newcount;
        }
    }
}

__attribute__((always_inline))
inline void pmu_print (struct pmu_desc *ctx) {
    struct pmu_conf *pmu_confs = ctx->pmu_confs;
    for (int i = 0; i < ctx->nconfs; ++i) {
        printf("%40s: tot=%8ld\n",
                pmu_confs[i].name,
                /* pmu_confs[i].min, */
                /* pmu_confs[i].diff, */
                pmu_confs[i].diff_sum);
    }
}
