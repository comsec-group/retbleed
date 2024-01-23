// SPDX-License-Identifier: GPL-3.0-only
#if defined(CONFIG_FUNCTION_TRACER)
#define CC_USING_FENTRY
#endif

#include <linux/sched.h>

// dump info has 8 x u64 entries
struct dump_info { u64 data[12]; };

// cant do them together, 512 is max allowed on stack
enum { AX, BX, CX,
    DX, DI, SI,
    R8, R9, R10,
    R11, R12, R13,
    R14, R15, BP,
    SP };

/* static int bpf_arr_sz = SP+1; */
// register dump. for kretprobe
BPF_ARRAY(rd, struct dump_info, SP+1);

// syscall dump. for syscall entry
BPF_ARRAY(sd, struct dump_info, 7);

BPF_ARRAY(sc_count_map, int, 1);
BPF_ARRAY(f_count_map, int, 1);

// event_info. All registers are inline so bcc can infer types automagically
struct event_info {
    unsigned char fun_name[32];
    unsigned char comm[TASK_COMM_LEN];
    // all this inlined instead of using a struct pt_regs. smelly..
    struct pt_regs regs;
};

BPF_PERF_OUTPUT(events);

#define DUMP_ARG(REG, reg) do {\
    idx = REG;\
    bpf_probe_read_kernel(newd.data,  sizeof(struct dump_info), (void *)(reg));\
} while(0)

#define DUMP_USER_ARG(reg) do {\
    bpf_probe_read_user(newd.data,  sizeof(struct dump_info), (void *)(reg));\
} while(0)


int do_return(struct pt_regs *ctx)
{
    struct event_info e = {};
    struct dump_info newd = {};
    int idx=0, sc_count, f_count, zero=0, *val;

    bpf_get_current_comm(e.comm, sizeof(e.comm));
    char *comm = e.comm;
    char fun[] = "krp";
    memcpy(e.fun_name, fun, sizeof(fun));
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id>>32;
    if (pid != PID) {
        // PID missmatch (common), do a poor man's compare on comm instead. This
        // is to include forks/clones in the process. TODO: Collect all PIDs
        // created and compare against all of them. Then we dont miss the
        // execve calls.
        COMM_COMPARE
    }

    val = f_count_map.lookup_or_try_init(&idx, &zero);

    // f_count will be -1 until SC_TARGET is reached
    if (val == NULL || *val == -1) return 0;

    // It's at the right sc_count, so do f_counting
    f_count = *val + 1;
    f_count_map.update(&idx, &f_count);

    // Is it our turn?
    if (f_count != F_TARGET) return 0;
    // F_TARGET reached and SC_TARGET reached. Dump time

    DUMP_ARG(AX, ctx->ax); rd.update(&idx, &newd);
    DUMP_ARG(BX, ctx->bx); rd.update(&idx, &newd);
    DUMP_ARG(CX, ctx->cx); rd.update(&idx, &newd);
    DUMP_ARG(DX, ctx->dx); rd.update(&idx, &newd);
    DUMP_ARG(SI, ctx->si); rd.update(&idx, &newd);
    DUMP_ARG(DI, ctx->di); rd.update(&idx, &newd);
    DUMP_ARG(R8, ctx->r8); rd.update(&idx, &newd);
    DUMP_ARG(R9, ctx->r9); rd.update(&idx, &newd);
    DUMP_ARG(R10, ctx->r10); rd.update(&idx, &newd);
    DUMP_ARG(R11, ctx->r11); rd.update(&idx, &newd);
    DUMP_ARG(R12, ctx->r12); rd.update(&idx, &newd);
    DUMP_ARG(R13, ctx->r13); rd.update(&idx, &newd);
    DUMP_ARG(R14, ctx->r14); rd.update(&idx, &newd);
    DUMP_ARG(R15, ctx->r15); rd.update(&idx, &newd);
    DUMP_ARG(BP, ctx->bp); rd.update(&idx, &newd);
    DUMP_ARG(SP, ctx->sp); rd.update(&idx, &newd);
    // maybe need to queue this data in an event prevent it from being overriden

    // copy the registers from ctx to my stuff
    bpf_probe_read_kernel(&e.regs, sizeof(struct pt_regs), (void *)ctx);

    events.perf_submit(ctx, &e, sizeof(struct event_info));
    return 0;
}

int end_call(struct pt_regs *ctx) {
    u32 idx = 0;
    int neg1 = -1;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, TASK_COMM_LEN);
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id>>32;
    if (pid != PID) {
        // PID missmatch (common), do a poor man's compare on comm instead. This
        // is to include forks/clones in the process. TODO: Collect all PIDs
        // created and compare against all of them. Then we dont miss the
        // execve calls.
        COMM_COMPARE
    }
    // reset counter. -1 means don't use
    f_count_map.update(&idx, &neg1);
    return 0;
}

#define MIN(a,b) ((a < b) ? a : b)
int do_call(struct pt_regs *ctx) {
    struct pt_regs sc_args = {};
    struct dump_info newd = {};
    int idx = 0;
    int zero = 0;
    int *val;
    int neg1= -1;
    f_count_map.update(&idx, &neg1); // -1 means don't even try to start
    int sc_count;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id>>32;
    if (pid != PID) {
        // PID missmatch (common), do a poor man's compare on comm instead. This
        // is to include forks/clones in the process. TODO: Collect all PIDs
        // created and compare against all of them. Then we dont miss the
        // execve calls.
        COMM_COMPARE
    }
    val = sc_count_map.lookup_or_try_init(&idx, &zero);
    if (val == NULL) return 1; // not possible. :(

    sc_count = *val + 1;
    sc_count_map.update(&idx, &sc_count);
    // Is it our turn?
    if (sc_count != SC_TARGET) return 0;

    // start f_count
    f_count_map.update(&idx, &zero);

    // This is the target syscall. Now we save the inputs for later inspection
    // reading pt_regs argument from syscall handler's first arg, rdi
    bpf_probe_read_kernel(&sc_args, sizeof(struct pt_regs), (void *)ctx->di);
    newd.data[0] = sc_args.di;
    newd.data[1] = sc_args.si;
    newd.data[2] = sc_args.dx;
    newd.data[3] = sc_args.cx;
    newd.data[4] = sc_args.r8;
    newd.data[5] = sc_args.r9;
    // 0th index is the arguments
    idx = 0; sd.update(&idx, &newd);

    // try dereference pointers i=1 => argument1. syscalls take at most 6 arguments. Will be 0s if not pointer
    idx = 1; DUMP_USER_ARG(sc_args.di); sd.update(&idx, &newd);
    idx = 2; DUMP_USER_ARG(sc_args.si); sd.update(&idx, &newd);
    idx = 3; DUMP_USER_ARG(sc_args.dx); sd.update(&idx, &newd);
    idx = 4; DUMP_USER_ARG(sc_args.cx); sd.update(&idx, &newd);
    idx = 5; DUMP_USER_ARG(sc_args.r8); sd.update(&idx, &newd);
    idx = 6; DUMP_USER_ARG(sc_args.r9); sd.update(&idx, &newd);

    return 0;
}
