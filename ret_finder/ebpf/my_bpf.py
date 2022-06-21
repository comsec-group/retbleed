#!/usr/bin/env python3
from __future__ import print_function
from bcc import BPF
import re
import sys
import argparse
import ctypes as ct
import os
import signal
from time import sleep
from sc_nargs import getNargs,scArgUseless

def get_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Detect POTENTIALLY controllable input"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    a = parser.add_argument

    a("--uid", "-u", required=True, type=int,
                        help="run under uid e.g., $(id -u kwikner)")
    a("--btb-fb", "-f", metavar="btb_fallbacks", required=True, type=str,
                        help="file path to btb fallback traces, we go over all of them")
    #  a("--krp", required=True, type=str, help="kretprobe symbol")
    #  a("--kp",  required=True, type=str, help="kprobe symbol")
    #  a("-s", required=True, type=int, help="Nth kprobe to be analyzed")
    #  a("-f", required=True, type=int, help="Nth kretprobe to be analyzed")
    a("--verbose", action="store_true", help="Print register contents always")
    a("test_prog", type=str, metavar="PROG",
                        help="path to process to trace")
    a("test_args", type=str, metavar="ARGS", nargs=argparse.REMAINDER,
                        help="process args")

    return parser.parse_args

ULONG8 = ct.c_uint64 * 12

REGS = [
    "RAX","RBX","RCX",
    "RDX","RDI","RSI",
    "R08","R09","R10",
    "R11","R12","R13",
    "R14","R15","RBP",
    "RSP","RIP"]

class CurrentRun():
    sc_nargs = 6
    sc_name = None
    sc_count = -1
    f_name = None
    f_count = -1
    logfile = None

class Global():
    parse_args = get_parser()
    args = None
    bpf_instance = None
    done = False
    current = CurrentRun()

class PTRegs(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("r15", ct.c_ulong),
        ("r14", ct.c_ulong),
        ("r13", ct.c_ulong),
        ("r12", ct.c_ulong),
        ("bp", ct.c_ulong),
        ("bx", ct.c_ulong), # callee clobbered..v
        ("r11", ct.c_ulong),
        ("r10", ct.c_ulong),
        ("r9", ct.c_ulong),
        ("r8", ct.c_ulong),
        ("ax", ct.c_ulong),
        ("cx", ct.c_ulong),
        ("dx", ct.c_ulong),
        ("si", ct.c_ulong),
        ("di", ct.c_ulong), # syscall number..v
        ("orig_ax", ct.c_ulong), # return frame for iretq
        ("ip", ct.c_ulong),
        ("cs", ct.c_ulong),
        ("flags", ct.c_ulong),
        ("sp", ct.c_ulong),
        ("ss", ct.c_ulong),
    ]

class EventInfo(ct.Structure):
    __TASK_COMM_LEN = 16
    __FUN_NAME_LEN = 32
    _pack_ = 1
    _fields_ = [
        ("fun_name", ct.c_char * __FUN_NAME_LEN),
        ("comm", ct.c_char * __TASK_COMM_LEN),
        ("regs", PTRegs)
    ]

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def msgverbose(*args, **kwargs):
    if not Global.args.verbose:
        return
    print(*args, **kwargs)

def lost_event(nlost):
    eprint(f"!!!!!! LOST {nlost} EVENTS", file=sys.stderr)

def logHitPart(inputReg, retReg, val):
    logTag("HITP", inputReg, retReg, val)

def logHit(inputReg, retReg, val):
    logTag("HIT", inputReg, retReg, val)

def logTag(tag, inputReg, retReg, val):
    msg = ";".join([
        Global.current.sc_name,
        Global.current.sc_count,
        inputReg,
        Global.current.f_name,
        Global.current.f_count,
        retReg,
        hex(val)
    ])
    Global.logfile.write(f"[{tag}] {msg}\n")

def logDetail(msg):
    lines = msg.split("\n")
    Global.logfile.writelines([f"[DETAIL] {l}\n" for l in lines])

# dump syscall args (and ptrs)
def dump_sd(sd):
    msg = ""
    msg += f"{Global.current.sc_name.ljust(72,':').rjust(80,':')}\n"
    for k, a in sd.items():
        # syscall arguments in k=0, and what they point to int k=1..5
        val = ct.cast(a.data, ct.POINTER(ct.c_uint64*12)).contents
        if k.value == 0:
            # first
            msg += "   "
            for x in range(0, Global.current.sc_nargs):
                regName = ["RDI","RSI","RDX","RCX","R08","R09"][x]
                msg += " %s: %016x" % (regName, val[x])
                msg += "\n   " if (x + 1)/ 3 == 0 else ""
            msg += "\n"
        elif k.value <= Global.current.sc_nargs:
            reg = ["", "*di","*si","*dx","*cx","*r8","*r9"][k.value]
            msg += f"    {reg}\t{ ' '.join(['{0:#0{1}x}'.format(x,18) for x in val]) }\n"
        else:
            # not taking more args in this syscall
            break
    logDetail(msg)

# dump return registers
def dump_rd(regs, rd):
    msg = ""
    msg += f"{Global.current.f_name.ljust(72, ':').rjust(80,':')}\n"
    msg += """    RAX: %016x RBX: %016x RCX: %016x
    RDX: %016x RSI: %016x RDI: %016x
    RBP: %016x R08: %016x R09: %016x
    R10: %016x R11: %016x R12: %016x
    R13: %016x R14: %016x R15: %016x
    RSP: %016x RIP: %016x\n""" % (regs.ax, regs.bx, regs.cx, regs.dx,
                                regs.si, regs.di, regs.bp, regs.r8,
                                regs.r9, regs.r10, regs.r11, regs.r12,
                                regs.r13, regs.r14, regs.r15, regs.sp,
                                regs.ip)
    for k, a in rd.items():
        regName = REGS[k.value]
        vals = ct.cast(a.data, ct.POINTER(ct.c_uint64*12)).contents
        msg += f"    {regName}\t{ ' '.join(['{0:#0{1}x}'.format(x,18) for x in vals]) }\n"
    logDetail(msg)

def print_event(cpu, data, size):
    bpf = Global.bpf_instance
    event = ct.cast(data, ct.POINTER(EventInfo)).contents
    fun_name = event.fun_name.decode()
    if fun_name != "krp":
        # does not happen.
        return
    to_check = []
    for k, a in bpf["sd"].items():
        # syscall arguments in k=0, and what they point to int k=1..5
        val = ct.cast(a.data, ct.POINTER(ct.c_uint64*12)).contents
        if k.value == 0:
            # first
            for x in range(0, Global.current.sc_nargs):
                regName = ["RDI","RSI","RDX","RCX","R08","R09"][x]
                if scArgUseless(Global.current.sc_name, regName):
                    continue
                if val[x] != 0:
                    to_check.append((regName, val[x]))
                if val[x] == 0:
                    continue
                vl = val[x]&0xffffffff
                vh = val[x]>>32
                if vl != 0 and vl != 0xffffffff:
                    to_check.append((regName+"-L", vl))
                if vh != 0 and vh != 0xffffffff:
                    to_check.append((regName+"-H", vh))
        elif k.value <= Global.current.sc_nargs:
            reg = ["", "*di","*si","*dx","*cx","*r8","*r9"][k.value]
            for i, x in enumerate(val):
                if x == 0:
                    continue
                name = f"{reg}+{(i*8):#04x}"
                to_check.append((name, x))
                vl = x&0xffffffff
                vh = x>>32
                if vl != 0 and vl != 0xffffffff:
                    name = f"{reg}+{(i*8):#04x}"
                    to_check.append((name+"-H", vl))
                if vh != 0 and vh != 0xffffffff:
                    name = f"{reg}+{(i*8+4):#04x}"
                    to_check.append((name+"-L", vh))
        else:
            # not taking more args in this syscall
            break
    regs = event.regs
    #  anyHit = False
    for i, val in enumerate([
            regs.ax, regs.bx, regs.cx,
            regs.dx, regs.di, regs.si,
            regs.r8, regs.r9, regs.r10,
            regs.r11, regs.r12, regs.r13,
            regs.r14, regs.r15, regs.bp,
            regs.sp, regs.ip]):
        regName = REGS[i]
        if val == 0:
            continue
        for hit in [r for (r,v) in to_check if v == val]:
            #  anyHit = True
            logHit(hit, regName, val)
        vl = val&0xffffffff
        vh = val>>32
        if vl != 0 and vl != 0xffffffff:
            for hit in [r for (r,v) in to_check if v == vl]:
                #  anyHit = True
                logHit(hit, regName, vl)
        if vh != 0 and vh != 0xffffffff:
            for hit in [r for (r,v) in to_check if v == vh]:
                #  anyHit = True
                logHit(hit, regName, vh)
    for k, a in bpf["rd"].items():
        regName = REGS[k.value]
        vals = ct.cast(a.data, ct.POINTER(ct.c_uint64*12)).contents
        for i, val in enumerate(vals):
            for hit in [r for (r,v) in to_check if v == val]:
                #  anyHit = True
                logHit(hit, f"{regName}+{(i*8):#04x}", val)
            vl = val&0xffffffff
            vh = val>>32
            if vl != 0:
                for hit in [r for (r,v) in to_check if v == vl]:
                    #  anyHit = True
                    logHitPart(hit, f"{regName}+{(i*8):#04x}", vl)
            if vh != 0:
                for hit in [r for (r,v) in to_check if v == vh]:
                    #  anyHit = True
                    logHitPart(hit, f"{regName}+{(i*8+4):#04x}", vh)
    dump_sd(bpf["sd"])
    dump_rd(regs, bpf["rd"])

def run_bpf(sc_name, sc_count, f_name, f_count, comm, test_args):
    Global.current.sc_nargs = getNargs(sc_name)
    Global.current.sc_name = sc_name
    Global.current.sc_count = sc_count
    Global.current.f_name = f_name
    Global.current.f_count = f_count
    if Global.current.sc_nargs == 0:
        # So far, we only look at syscall inputs,
        # however, in future, we may want to look at previous syscall inputs
        return
    # we kprobe to see the args that we control in
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        # child
        os.close(write_fd)
        os.setuid(Global.args.uid)
        os.read(read_fd, 1)
        os.close(read_fd)
        #  sleep(1)
        # block until our parent is tracing our movements...
        # TODO execl comm with args..
        os.execv(Global.args.test_prog, test_args)
        exit(1) # unreachable
    # parent
    os.close(read_fd)

    with open(f"{os.path.dirname(__file__)}/trace_regs.c") as f:
        text = f.read()

    compare = ""
    for i, c in enumerate(comm):
        if i >= 16:
            break
        compare += f"if ('{c}' != comm[{i}]) return 0;\n"

    # replaces all
    text = text.replace("PID", str(pid))
    text = text.replace("COMM_COMPARE", compare)
    text = text.replace("F_TARGET", str(f_count))
    text = text.replace("SC_TARGET", str(sc_count))

    bpf = BPF(text = text, cflags=["-Wno-macro-redefined"])

    Global.bpf_instance = bpf

    print(f"comm={comm}; kretprobe={f_name}; syscall={sc_name}; s={sc_count} f={f_count}");

    try:
        bpf.attach_kretprobe(event=f_name, fn_name="do_return")
        bpf.attach_kprobe(event=sc_name, fn_name="do_call")
        bpf.attach_kretprobe(event=sc_name, fn_name="end_call")
    except Exception:
        os.kill(pid, signal.SIGINT)
        bpf.cleanup()
        bpf = None
        Global.bpf_instance = None
        return

    # lots of stuff can come in here. We may also increase the perf buffer size
    # and retry
    #  PERF_BUF_SZ = 4<<30
    # 1GiB seems like max..
    bpf["events"].open_perf_buffer(print_event, lost_cb=lost_event)

    print("Tracing... Hit Ctrl-C to end.")
    os.write(write_fd, b"x")

    # Sometimes the result simply never arrives so abort after 4 seconds.
    start_time_ms = int(BPF.monotonic_time() / 1000000)
    bpf.perf_buffer_poll(timeout=4000)
    elapsed_ms = int(BPF.monotonic_time() / 1000000) - start_time_ms
    if elapsed_ms >= 3999:
         Global.logfile.write(f"[TIMEOUT] {sc_name};{sc_count};{f_name};{f_count}\n")
    try:
        bpf.cleanup()
    except Exception:
        eprint("Unable to cleanup bpf")
    #  bpf.detach_kretprobe(event=f_name)
    #  bpf.detach_kprobe(event=sc_name)
    #  if sc_name != f_name:
        #  bpf.detach_kretprobe(event=sc_name)
    # pray you will get cleaned up
    bpf = None
    Global.bpf_instance = None
    try:
        os.kill(pid, signal.SIGINT)
    except:
        # process already dead. good.
        pass

def main():
    Global.args = Global.parse_args()
    test_prog = Global.args.test_prog
    if not test_prog:
        print("Missing required PROG")
        exit(1)

    # should be empty, to not override previous results.
    #  os.mkdir("./output",)
    comm = os.path.basename(Global.args.test_prog)
    test_args = [ comm ]
    if Global.args.test_args:
        for a in Global.args.test_args:
            test_args.append(a)
    logfileName = f"output/{'-'.join(test_args)}.txt"
    Global.logfile = open(logfileName, "w")
    print(f"Logging output to {logfileName}")

    with open(Global.args.btb_fb, "r") as f:
        for l in f.readlines():
            [sc_name, sc_count, f_name, f_count, L] = l.split(";")
            #  if re.search(r"sys_write|sys_exit_group", sc_name):
                # skip noisy ones. they are included in pretty much every test
                #  continue
            run_bpf(sc_name, sc_count, f_name, f_count, comm, test_args)

if __name__ == "__main__":
    main()
