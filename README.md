RETBleed Artifact
-----------------

Demo of leaking /etc/shadow contents on Intel and AMD
https://www.youtube.com/watch?v=dmSPvJxPm80 

## Reverse engineering
- `./retbleed_zen/pocs/ret_bti` finds the patterns that cause BTB collisions.
- `./retbleed_zen/pocs/cp_bti` shows that collisions happen across.
- `./retbleed_intel/pocs/ret_bti` shows that returns go via BTB.
- `./retbleed_intel/pocs/cp_bti` shows that we can train across kernel returns
  in user space.

Refer to the manuals ([AMD](./retbleed_zen/pocs), [Intel](./retbleed_intel)).

- [`./rsb_depth_check`](./rsb_depth_check) shows that there is an RSB
    that is used. And for Intel, it also indicates that some other prediction
    mechanism is taking place.
- `./zen_ras_vs_btb` is illustrated in Figure 5. It shows that Return Addres
    Stack (RAS, aka RSB) is not used on Zen2 when there's a BTB entry. To
    evaluate Zen/+ `BTI_PATTERN` must be manualy changed.

## Framework

Please refer to section 4.2 of the paper.

1. *Detecting vulnerable returns.* We do this with `./ret_finder/funcgraph` and `./ret_finder/tools/trace_underfill.py`. Refer to the [manual](./ret_finder).
2. *Identifying exploitable returns.* We do this in [`./ret_finder/ebpf`](./ret_finder#ebpfmy_bpfpy-detect-controllable-input).
3. *Finding compatible disclosure gadgets.* We do this in [`./gadget_scanner`](./gadget_scanner)
4. *Detecting branch history at the victim return.* We do this in [`./bhb_generate`](./bhb_generate)

## Evaluation.

Make sure to use an affected system (ref. Table 1).

We evaluate the following:

1. Leakage rate with ideal gadgets.
2. Leakage rate with our discovered gadgets
3. Leaking /etc/shadow

### Optimal leakage rate
_Requires root and at least 1 huge page enabled._
We use `./{retbleed_zen,retbleed_intel}/pocs/eval_bw`, which depend on the
gadgets in `./{retbleed_zen,retbleed_intel}/pocs/kmod_retbleed_poc`. We run
`eval_bw` 11 times and use the median leakage rate and accuracy. To evaluate
Zen/+, update `PWN_PATTERN` in `eval_bw.c`. 

### Leakage rate with our discovered gadgets

**AMD.** Go to  `./retbleed_zen/exploits/`. To get kernel_text, run
`./break_kaslr`. Then use the `./do_retbleed.sh`.

```
usage: ./do_retbleed.sh <kernel_text> [core_id=0] [leak_perf]
  unless leak_perf is set (to anything), try to leak /etc/shadow
```

We run this 100 times and use the median leakage rate and accuracy of the runs
that succeeded. 


**Intel.** Go to `./retbleed_intel/exploits/`. To get kernel_text, we use MDS,
run ./break_kaslr on two threads on the same core. On a 6 core cpu it could be
`taskset -c 1,7 ./break_kaslr`. Then use `./do_retbleed.sh`

```
usage: ./do_retbleed.sh <kernel_text> [core_id=0] [--leak_perf]
  unless --leak_perf is set (to anything), try to leak /etc/shadow
```

### Leaking /etc/shadow
Same as above, but omit the last arg, `--leak_perf`. As shown in the demos, we can
parallelize it to make it go faster.

