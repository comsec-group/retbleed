# SPDX-License-Identifier: GPL-3.0-only
import gdb

KB_base = 0xffffffff81000000

# XXX: can we get the KB someway with GDB?
# Check where your kernel starts inside the guest, `grep ' _text$'
# /proc/kallsyms` and put here. It's annoying -- sorry.
KB = 0xffffffff93000000
# By the way, we're hardcoded to target the ip6 gadget.

def reg(name):
    return int(gdb.selected_frame().read_register(name))

# This didn't work at all. Lol
class SilentStep(gdb.Command):
    def __init__(self):
        super (SilentStep, self).__init__ ("ssi", gdb.COMMAND_OBSCURE)
    def invoke(self, arg, from_tty):
        gdb.execute("si", from_tty=False, to_string=True)
SilentStep()


# ended up not using. but maybe fun to have.
def irq_disable():
    gdb.execute("call *0xffffffff81114410")
def irq_enable():
    gdb.execute("call *0xffffffff81113f10")

class Offs:
    pvclock_clocksource_read = 0xffffffff81076a40
    ip6_local_out = 0xffffffff81adf410
    ip6_local_out_RET = 0xffffffff81adf454
    unk_intr_kmod = 0xffffffffc0002872
    unk_intr = 0xffffffff8155904d
    u__sysvec_apic_timer_interrupt = 0xffffffff810653c0
    asm_call_irq_on_stack = 0xffffffff81c010d0

    kvm_steal_clock = 0xffffffff81074dc0
    kvm_steal_clock_RET = 0xffffffff81074dfe

    kvm_clock_get_cycles = 0xffffffff81075c90
    kvm_clock_get_cycles_RET = 0xffffffff81075ca1

    kvm_sched_clock_read = 0xffffffff81075cb0
    kvm_sched_clock_read_RET = 0xffffffff81075cb9

    ktime_get_update_offsets_now = 0xffffffff81134c40
    ktime_get_update_offsets_now_RET = 0xffffffff81134d28


hist_break = [
    #  { "disable": True, "name": "__do_softirq#call#wake_up_process", "stop_at":0xffffffff81e00282, "skip_to":0xffffffff81e00287 },

    { "disable": False, "name": "try_to_wake_up#call#update_rq_clock", "stop_at": 0xffffffff810d619e, "skip_to": 0xffffffff810d61a3 },

    #  { "disable": True, "name": "try_to_wake_up#call#ttwu_do_activate", "stop_at": 0xffffffff810d61b0, "skip_to": 0xffffffff810d61b5, },

    #  { "disable": True, "name": "ttwu_do_wakeup#call#check_preempt_curr", "stop_at": 0xffffffff810d3fe9, "skip_to": 0xffffffff810d3fee, },
    { "disable": False, "name": "check_preempt_curr#call#resched_curr", "stop_at": 0xffffffff810d3f89, "skip_to": 0xffffffff810d3f8e},


    { "disable": False, "name": "psi_task_change", "stop_at": 0xffffffff810fdc00, "skip_to": 0xffffffff810fdc32, }
]

for m in [attr for attr in dir(Offs) if not callable(getattr(Offs, attr)) and not attr.startswith("__")]:
    setattr(Offs, m, getattr(Offs, m) - KB_base + KB)
for e in hist_break:
    e["stop_at"]  = e["stop_at"] - KB_base + KB
    e["skip_to"] = e["skip_to"] - KB_base + KB
# fix up for KASLR.. done..


CFG_EDGE = [
    "ret", "retf", "retfq",
    "iret", "jae", "ja", "jbe",
    "jb", "jcxz", "jecxz", "je",
    "jge", "jg", "jle", "jl",
    "jmp", "jne", "jno", "jnp", "jns",
    "jo", "jp", "jrcxz", "js", "call"
] + [ # gdb-10 doesn't have these. gdb 9 does
    "retq",
    "callq",
    "jmpq"
]

def insn_is_cfgedge(insn):
    mnemonic = insn["asm"].split(" ")[0]
    return mnemonic in CFG_EDGE


class Mybreak(gdb.Breakpoint):
    def stop(self):
        gdb.execute(f"trace-pc-range {Offs.ip6_local_out_RET}")
        return False

class LogCFEdges(gdb.Command):
    def __init__(self):
        super (LogCFEdges, self).__init__ ("trace-pc-range", gdb.COMMAND_OBSCURE)
    def invoke(self, arg, from_tty):

        argv = gdb.string_to_argv(arg)
        stop = int(argv[0],0)
        arch = gdb.selected_frame().architecture()
        # the next pc anticipated in this basic block. If the next pc turns out
        # to be a different value then we encountered a control flow edge which
        # we want to trace.
        current_pc = reg("pc")
        prev_insn = arch.disassemble(current_pc)[0]
        logfile = open("log.txt", "w+")

        gdb.execute("set pagination off")
        # skip over rdtsc part, avoid getting stuck
        bp = gdb.Breakpoint(f"*{Offs.kvm_clock_get_cycles_RET}")
        bp.enabled = False

        bp_kvm = gdb.Breakpoint(f"*{Offs.kvm_steal_clock_RET}")
        bp_kvm.enabled = False
        # b *0xffffffff81adf410
        # ret : 0xffffffff81adf454
        #  irq_disable()
        dist = stop - reg("pc")
        print(f"{dist} instruction ahead is the stop")
        my_thread = gdb.selected_thread()

        bp.thread = my_thread.num
        bp_kvm.thread = my_thread.num
        logfile.write("start===================\n")
        while True:
            if my_thread.num != gdb.selected_thread().num:
                print("Why you switch??")
                break
                my_thread.switch()
            #gdb.execute("ssi", to_string=True)
            gdb.execute("si")
            prev_insn = arch.disassemble(current_pc)[0]
            current_pc = reg("pc")
            if current_pc == Offs.asm_call_irq_on_stack:
                print("Wow you're interruped")
                print(f"Check cur= {hex(current_pc)} prev= {hex(prev_insn['addr'])}")
                break
            if current_pc == Offs.u__sysvec_apic_timer_interrupt:
                print("Wow you're interruped")
                print(f"Check cur= {hex(current_pc)} prev= {hex(prev_insn['addr'])}")
                break
##            if current_pc == 0xffffffff81076a55:
##                print("FUCKL ME")
##                break
            entry_triggered = None
            for entry in hist_break:
                if entry["disable"]:
                    continue
                if entry["stop_at"] == current_pc:
                    entry_triggered = entry
            if entry_triggered:
                e = entry_triggered
                print(f"BREAK HISTORY: {e['name']}")
                logfile.write(f"  ?????? {hex(current_pc-KB)} {e['name']}\n")
                tmpbp = gdb.Breakpoint(f"*{e['skip_to']}", temporary=True)
                tmpbp.thread = my_thread.num
                gdb.execute("cont")
                current_pc = reg("pc")
                continue
            #  if current_pc == 0xffffffff81e00282:
            #      # this one makes it work but history too small
            #      print("BREAK HISTORY")
            #      tmpbp = gdb.Breakpoint("*$pc+5", temporary=True)
            #      tmpbp.thread = my_thread.num
            #      gdb.execute("cont")
            #      continue
            if current_pc == (0xffffffff81131d55 - KB_base + KB):
                print("BREAK HISTORY")
                logfile.write(f"  ?????? ")
                tmpbp = gdb.Breakpoint("*$pc+5", temporary=True)
                tmpbp.thread = my_thread.num
                gdb.execute("cont")
                current_pc = reg("pc")
                continue
            if current_pc == Offs.ktime_get_update_offsets_now:
                print("BREAK HISTORY")
                logfile.write(f"  ?????? {hex(current_pc-KB)} Offs.ktime_get_update_offsets_now\n")
                tmpbp = gdb.Breakpoint(f"*{Offs.ktime_get_update_offsets_now_RET}",
                                       temporary=True)
                tmpbp.thread = my_thread.num
                gdb.execute("cont")
                current_pc = reg("pc")
                continue
            if current_pc == Offs.kvm_sched_clock_read:
                print("BREAK HISTORY")
                logfile.write(f"  ?????? {hex(current_pc)} Offs.kvm_sched_clock_read\n")
                tmpbp = gdb.Breakpoint(f"*{Offs.kvm_sched_clock_read_RET}",
                                       temporary=True)
                tmpbp.thread = my_thread.num
                gdb.execute("cont")
                current_pc = reg("pc")
                continue
            if current_pc == Offs.kvm_steal_clock:
                print("BREAK HISTORY")
                logfile.write(f"  ?????? {hex(current_pc)} Offs.kvm_steal_clock\n")
                bp_kvm.enabled = True
                bp_kvm.thread = my_thread.num
                gdb.execute("cont")
                bp_kvm.enabled = False
                current_pc = reg("pc")
                continue
            if current_pc == Offs.kvm_clock_get_cycles:
                print("BREAK HISTORY")
                logfile.write(f"  ?????? {hex(current_pc)} Offs.kvm_clock_get_cycles\n")
                bp.enabled = True
                bp.thread = my_thread.num
                gdb.execute("cont")
                bp.enabled = False
                current_pc = reg("pc")
                continue
            if current_pc != prev_insn["addr"] + prev_insn["length"]:
                if not insn_is_cfgedge(prev_insn) or current_pc == Offs.unk_intr_kmod:
                    tmp_bp = gdb.Breakpoint(f"*{prev_insn['addr'] + prev_insn['length']}", temporary=True)
                    tmp_bp.thread = my_thread.num
                    print(f"Interrupted! cur={hex(current_pc)} prev={hex(prev_insn['addr'])} {prev_insn['asm']}")
                    logfile.write(f"  ?????? {hex(current_pc)} Interrupt prev={hex(prev_insn['addr'])} {prev_insn['asm']}\n")
                    gdb.execute("cont")
                    current_pc = reg("pc")
                    continue
                else:
                    # new basic block. so we log src and dst (dst=current_pc)
                    # src is assumed to be the last byte of the branch
                    src = prev_insn["addr"] + prev_insn["length"] - 1
                    dst = current_pc
                    #msg = f"  {{ .src={hex(src)}, .dst={hex(dst)} }}, // {hex(prev_insn['addr'])} {prev_insn['asm']}"
                    msg = "  { .src=0x%06x, .dst=0x%06x }, // 0x%06x %s" % (src-KB,dst-KB,prev_insn['addr']-KB,prev_insn['asm'])
                    print(msg)
                    logfile.write(msg+"\n")

            if prev_insn['addr'] == stop:
                print("Yes!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                logfile.write(f"OK!\n")
                break
        gdb.execute("set pagination on")
        logfile.write("end========================\n")
        logfile.close()
        #  irq_enable()
LogCFEdges()

#gdb.execute("target remote :1234")
#IP6_GADGET = False
IP6_GADGET = True
if IP6_GADGET:
    print(f"*{Offs.ip6_local_out}")
    gdb.Breakpoint(f"*{Offs.ip6_local_out}", temporary=True)
    gdb.execute("cont")
    gdb.Breakpoint(f"*{0xffffffff81970852-KB_base+KB}", temporary=True)
    gdb.execute("cont")
    gdb.execute(f"trace-pc-range {0xffffffff81a8f290-KB_base+KB}")
#    gdb.execute("trace-pc-range 0xffffffff81adf454")
else:
    handle_ioctl = 0xffffffffc0681420 - KB_base + KB
    go_home = handle_ioctl & 0xfffffffffffff000 - KB_base + KB
    reload_ = 0xffffffffc06815a1- KB_base + KB
    # a bit annoying because the module can get a different location every
    # boot, nokalsr does not really help.
    #gdb.Breakpoint(f"*{0xffffffff81305f45}", temporary=True)
    #gdb.Breakpoint(f"*{handle_ioctl}", temporary=True)
    gdb.Breakpoint(f"*{0xffffffff813915e0}", temporary=True)
    #gdb.Breakpoint(f"*{0xffffffffc04c742d}", temporary=True)
    #gdb.Breakpoint(f"*{0xffffffffc048942d}", temporary=True)
    gdb.execute("cont")
    print(f"HIT the BP @ {hex(handle_ioctl)}")
    gdb.execute(f"trace-pc-range {reload_}")
    #print(f"trace-pc-range {hex(go_home)}")

