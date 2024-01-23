# SPDX-License-Identifier: GPL-3.0-only
#!/bin/bash
CORES=( $(grep core\ id /proc/cpuinfo | sort | uniq | cut -d: -f2 | bc) )

for C in ${CORES[@]:1}; do
  tmux split-window "time ./do_retbleed.sh $1 $C && read"
  tmux select-layout tiled
done

time ./do_retbleed.sh $1 ${CORES[0]}
read A
