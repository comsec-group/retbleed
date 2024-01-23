# SPDX-License-Identifier: GPL-3.0-only
#!/bin/bash
# This script is executed from ./funcgrap

# this will file could enjoy becoming native some day.

# For this to work well for longer tests, make the perf buffer huge.
#echo 10000000 > per_cpu/cpu$CPU/buffer_size_kb

if  [ `whoami` != "root" ]; then
  # this odes not work.. signal does not prepagate to sudo process
  echo need root!
  # sudo $0 $@ &
  exit 0
fi

tracefs=/sys/kernel/debug
PID=$1

CPU=$3
CPU_MASK=$(echo "obase=16; $[1<<$3]" | bc)

while ! echo nop > $tracefs/tracing/current_tracer; do
  sleep 0.1
done

# cat $tracefs/tracing/per_cpu/cpu$CPU/buffer_size_kb

echo 0 > $tracefs/tracing/tracing_on
echo $1 > $tracefs/tracing/set_ftrace_pid
# follow forks
echo function-fork >> $tracefs/tracing/trace_options

echo function_graph > $tracefs/tracing/current_tracer

# ignore
echo irq_enter_rcu > $tracefs/tracing/set_graph_notrace
echo unmap_page_range >> $tracefs/tracing/set_graph_notrace
echo pagevec_lru_move_fn >> $tracefs/tracing/set_graph_notrace
echo _cond_resched >> $tracefs/tracing/set_graph_notrace
# ignoring interrupts
echo nofuncgraph-irqs >> $tracefs/tracing/trace_options

# this takes a few seconds..
echo '__x64_sys_*' > $tracefs/tracing/set_graph_function
echo '__do_sys_*' >> $tracefs/tracing/set_graph_function
echo '__x32_compat_sys_*' >> $tracefs/tracing/set_graph_function

# include } /* fn_sym */ so we can trace..
echo funcgraph-tail > $tracefs/tracing/trace_options

# remove clutter.
echo nofuncgraph-duration >> $tracefs/tracing/trace_options
echo nofuncgraph-cpu >> $tracefs/tracing/trace_options
echo nocontext-info >> $tracefs/tracing/trace_options
echo nofuncgraph-overhead >> $tracefs/tracing/trace_options

# cpu mask = only 15, 2**15
# cpu mask = only 5, 2**5
echo $CPU_MASK > $tracefs/tracing/tracing_cpumask
echo 1 > $tracefs/tracing/tracing_on

echo GO cpid=$PID ## this the first output
cat $tracefs/tracing/trace_pipe > $2
