# SPDX-License-Identifier: GPL-3.0-only
#!/bin/bash
set -e

mkdir -p output

COMM=$(basename $1)
ARGS=${@:2}

FG_BIN=$(dirname $0)/funcgrap/funcgrap
FG_SH=$(dirname $0)/funcgrap/fgtrace.sh
TRACE_UF=$(dirname $0)/tools/trace_underfill.py
BPF=$(dirname $0)/ebpf/my_bpf.py

LOG_PATH="output/${COMM}_${ARGS// /-}_raw.txt"
BTB_PATH="output/${COMM}_${ARGS// /-}_btb.txt"

echo COMM=$COMM
echo ARGS=$ARGS
echo WARMUP....

# need to run as unprivileged, also "warmup"
(sudo -u $SUDO_USER $@) 2>&1 | grep -q 'needs to be run as root' && echo $COMM >> needs_root.txt

# a bit clonky, funcgrap is setuid process to elivate. but the bpf does the
# opposite; it runs as root and drops privileges instead.
if [ ! -z "$ARGS" ]; then
  sudo -u $SUDO_USER $FG_BIN -p 5 -t $FG_SH -o $LOG_PATH "$1 $ARGS"
else
  sudo -u $SUDO_USER $FG_BIN -p 5 -t $FG_SH -o $LOG_PATH "$1"
fi

$TRACE_UF < $LOG_PATH > $BTB_PATH
sudo $BPF --uid=$(id -u $SUDO_USER) --btb-fb $BTB_PATH $@
