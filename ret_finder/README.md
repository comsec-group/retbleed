RET finder framework
---------
*Find bleedable RETs in the kernel.*

We assume that you are running the kernel that you wish to exploit on a system
that is fairly similar to the targeted one. 

# `./process_binary.sh` 
`./process_binary.sh` runs the whole toolchain on a single binary. Running over
the entire ltp syscall suite takes several hours and takes unnecessary amount of
time through this command, however. Instead, only run `funcgrap` over
each ltp test and analyze the logs in parallell. Some example outputs are given
in `./output.tar.gz`. Note that some very large raw outputs were deleted.

### `funcgrap/` Collecting function graphs. 
Keep in mind that long-running binaries risk consuming the entire perf buffer,
which leads to lost data. This happens with ltp because it includes some stress
tests. To prevent this, make the perf buffer large or exclude for example
`msgstress0{1..4}`.

```bash
  # gives almost 10GiB to perf, maybe set it to 5 GiB if it's too much. 
  echo 10000000 | sudo tee /sys/kernel/debug/tracing/per_cpu/cpu3/buffer_size_kb
```
Note that by default, `funcgrap` pins the tested binary to CPU core 3.

To run the entire ltp syscall suite, install ltp and use
`./funcgrap/run_full_suite.sh <result_path>`. To run all tests and place each
result in `<result_path>`. If you install ltp with $DESTDIR different from
default `/`, configre $LTP_ROOT in `./funcgrap/run_full_suite.sh` accordingly.

### `tools/trace_underfill.py` Discover deep call stacks
Find vulnerable returns on Intel (all returns are vulnerable on AMD). Reads
trace output as provided by `funcgraph` into its stdout and produces a
semicolon-seperated list of locations where vulnerable returns occured. For
example: `./tools/trace_underfill.py < ./output/raw/recvmsg02__raw.txt`. The
columnns are, for example.

| syscall   | Nth invocation of ditto | Vuln. func. | Nth call to vuln. func. in syscall | Raw input line# |
|-----------------|-:|-------------|-:|--:|
| `__x64_sys_execve`|1|`vfs_open`      |1 |791 |
| `__x64_sys_execve`|1|`do_open.isra.0`|1 |800 |
| `__x64_sys_execve`|1|`path_openat`   |1 |807 |

### `ebpf/my_bpf.py` Detect controllable input

This is a poorly named bcc/ebpf program. It takes the binary to run as input and
also the semicolon-separated list of vulnerable syscalls, such as those in
`output/btb`. `./my_bpf.py -h` for details. We try as much as we can to exclude
system call with input parameters that are cumbersome or difficult to control
(for example flags, file descriptors). It produces output such as shown in
`output/`

### Parsing the output

The following shows a list of how many 64-bit wide memory chunks that we
control next to the vulnerable function. For example, `5 udp_v6_send_skb.isra.0`
means we control five 64-bit memory chunks in `udp_v6_send_skb.isra.0` that are
pointed to, within a 96 byte range, by some register. 

```bash
# 1 or more 64-bit chunks of memory
grep -E ';.+\+0x.+;0x.{16,}$' output/*.txt | awk -F';' '{print $4 ";" $3}' | sort | uniq | cut -d ';' -f 1 | uniq -c | sort -n

# 1 or more 64-bit registers
grep -E ';[^+]+;0x.{16,}$' output/*.txt | awk -F';' '{print $4 ";" $3}' | sort | uniq | cut -d ';' -f 1 | uniq -c | sort -n 

# 1 or more 47-bit registers
grep -E ';[^+]+;0x.{12,}$' output/*.txt | awk -F';' '{print $4 ";" $3}' | sort | uniq | cut -d ';' -f 1 | uniq -c | sort -n 

# vuln. syscalls
cat output/btb/*.txt | cut -d';' -f1 | sort | uniq | wc -l

# vuln. rets
cat output/btb/*.txt | cut -d';' -f3 | sort | uniq | wc -l

# total tests (-459 that need root)
grep . /opt/ltp/runtest/syscalls | grep -v '#' | less  
```

