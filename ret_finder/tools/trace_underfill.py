# SPDX-License-Identifier: GPL-3.0-only
#!/usr/bin/env python3

DEBUG=False
import sys
import re

import fileinput

RSB_SZ=16

# if we trace a syscall we should take into a account that  we're already called
# do_syscall_64
#   __x64_sys_SC so depth is 2
START_DEPTH=0
depth = START_DEPTH
# the thing is ... do_syscall_64 might do stuff before returning and we're not
# allowed to probe it.

# funcgraph entry name
sc_name = ""

# syscall being on hold because of context switch
syscall_on_hold = { }

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# fast forwarding to a new syscall.
fast_forward_mode = False
class RSBEntry:
    valid = True
    callsite = None
    def __init__(self, callsite):
        self.callsite = callsite
    def invalidate(self):
        self.valid = False

rsb = [ RSBEntry("RSB_REFILL") for x in range(16) ]

li=0 # line index

# for each syscall keep track of how many calls
sc_count = {}

# keep track of how many times each function is called. on a new syscall, clear
# this dict.
f_count = {}

# don't give syscall;*;fallback;N more than once,
# we don't wana trace the 100th write in the same fallback anyway.
seen =[]

for l in fileinput.input():
    li+=1
    if "LOST" in l:
        # Lost events... we dont know how we came to the next line.
        # Fast-forward until depth=0 and restart.
        fast_forward_mode = True
        continue
    if "--------------------" in l:
        # If there is a context switch we can continue there but we probably
        # wont know which syscall we were in
        # fast_forward_mode = False
        rsb = [ RSBEntry("RSB_REFILL") for x in range(16)]
        # process switching possilby due to scheduler. the following calls are
        # from a different process and might not be easily reproducable
        continue
    if "=>" in l:
        # Now comes the context switching.
        m = re.match(".+-([0-9]+).*=>.*-([0-9]+)", l)
        #context switch
        if not m:
            eprint("unprocessable", l)
        cs_from = m[1]
        cs_to = m[2]
        # here's a dragon: we switch call stack so we might have a large depth
        # now and come to depth=START_DEPTH (very common) =>handled
        syscall_on_hold[cs_from] = sc_name
        if cs_to in syscall_on_hold:
            sc_name = syscall_on_hold[cs_to]
        # this part may be unnecessary now that I've seen that context switching
        # always results in rsb refilling.. and conditional ibpb. but I guess if
        # you return 17 times it can still work.

        # cond_ibpb prevents further calls to have any effect.
        fast_forward_mode = True
        continue
    if not "{" in l and "}" not in l:
        # not going into or out. so useless.
        continue
    # we know we're either calling or returning (otherwise no opening or closing
    # brace)
    line = l.rstrip()
    newdepth = 0
    for x in line:
        if x != " ":
            break
        newdepth += 1
    # divide by two because two spaces = 1 step deeper
    depth = newdepth>>1
    if fast_forward_mode and depth != START_DEPTH:
        continue
    # back to a sane starting point.
    fast_forward_mode = False
    sym_name = re.sub("[{}*/() ]|\[.*\]", "", line)
    if depth == START_DEPTH and "{" in l:
        sc_name = sym_name
        f_count.clear()
        if not sc_name in sc_count:
            sc_count[sc_name] = 0
        sc_count[sc_name] += 1
    if not sym_name in f_count:
        f_count[sym_name] = 0
    if "{" in l:
        # call
        rsb[depth%RSB_SZ] = RSBEntry(sym_name)
        if DEBUG:
            print(f"depth={depth}=True {sym_name} {li}")
    if "}" in l:
        # return
        f_count[sym_name] += 1
        if DEBUG:
            print(f"depth={depth}=False {sym_name} {li}")
        if not rsb[depth%RSB_SZ].valid:
            # this RSBEntry has previously been used! This means we have to
            # switch from RSB to the alternative, vulnerable predictor.
            tag = f"{sc_name};*;{sym_name};{f_count[sym_name]};x"
            if not tag in seen:
                seen.append(tag)
                print(f"{sc_name};{sc_count[sc_name]};{sym_name};{f_count[sym_name]};{li}")
        # invalidate current rsb entry
        rsb[depth%RSB_SZ].invalidate()
