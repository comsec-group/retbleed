RET finder framework
---------
*Find bleedable RETs in the kernel.*

We assume that you are running the kernel that you wish to exploit on a system
that is fairly similar to the targeted one. We provide example outputs in
`./output.tar.gz` if you do not want to run the entire suite. Note that we
excluded some particularily large raw outputs. 

### Linux test project
To reproduce our results, build and install `./ltp`. 


### `./process_binary.sh` 
`./process_binary.sh` runs the whole toolchain on a single binary, which is
useful to verify that the toolchain works. For example, `sudo ./process_binary.sh
/opt/ltp/testcases/bin/recvmsg02` should produce three txt files under
`./output_process_binary/`

Running over the entire ltp syscall testsuite takes unnecessarily long this way,
beacuse it will not parallelize. Instead, run `funcgrap` over each ltp test and
analyze the logs in parallell, which we will discuss next. 

### `funcgrap/` Collecting function graphs. 
Long-running binaries risk consuming the entire perf buffer, which results in
data loss. This happens with ltp, because it includes some stress tests. To
prevent this, make the perf buffer large and/or exclude for example
`msgstress0{1..4}`.

```bash
  # gives almost 10GiB to perf. 5 GiB may work too.
  echo 10000000 | sudo tee /sys/kernel/debug/tracing/per_cpu/cpu3/buffer_size_kb
```

Note that by default, `funcgrap` pins the tested binary to CPU thread 3.

To run the entire ltp syscall suite, use `./funcgrap/run_full_suite.sh
<result_path>`. To run all tests and place each result in `<result_path>`. If
you installed ltp with a `DESTDIR` that is different from the default, configre
`LTP_ROOT` in `./funcgrap/run_full_suite.sh` accordingly.

### `tools/trace_underfill.py` Discover deep call stacks
Find vulnerable returns on Intel (all returns are vulnerable on AMD). Reads
trace output, provided by `funcgraph`, from stdin and writes a
semicolon-seperated list of locations where vulnerable returns occured to
stdout. For example: `./tools/trace_underfill.py <
./output/raw/recvmsg02__raw.txt`. The columnns are, for example.

| syscall   | Nth invocation of ditto | Vuln. func. | Nth call to vuln. func. in syscall | Raw input line# |
|-----------------|-:|-------------|-:|--:|
| `__x64_sys_execve`|1|`vfs_open`      |1 |791 |
| `__x64_sys_execve`|1|`do_open.isra.0`|1 |800 |
| `__x64_sys_execve`|1|`path_openat`   |1 |807 |

More example outputs are found under `./output/btb`. These locations have
vulnerable returns, in the sense that we can control the return target. But, to
leak arbitrary memory, we need control over the registers or memory that they
reference.

### `ebpf/my_bpf.py` Detect controllable input

This is a poorly named bcc/ebpf program. It takes the testcase binary and
the semicolon-separated list of its vulnerable returns. Examples of such lists
are found under `./output/btb`. Run `./my_bpf.py -h` for details. We try as
much as we can to exclude system call with input parameters that are cumbersome
or difficult to control (for example flags, file descriptors). It produces
output such as shown in `output/`.

### Parsing the output

The following shows a list of the number of 64-bit wide memory chunks that we
control upon a vulnerable return. For example, `5 udp_v6_send_skb.isra.0`
means we control five 64-bit memory chunks in `udp_v6_send_skb.isra.0` that are
pointed to, within a range of 96 bytes, by some register. 

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

