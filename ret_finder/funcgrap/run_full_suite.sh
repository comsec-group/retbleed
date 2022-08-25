#!/bin/bash
cd "$(dirname "$0")"

ROUND_PATH=$1
if [ -z "$ROUND_PATH" ]; then
	echo "required ROUND_PATH"
	exit 2
fi

mkdir -p "$ROUND_PATH" || exit 1
mkdir -p "$ROUND_PATH/out" || exit 1;

FUNCGRAP_PATH="$(readlink -f ../funcgrap/funcgrap)"
FGTRACE_PATH="$(readlink -f ../funcgrap/fgtrace.sh)"

LTP_ROOT=/opt/ltp

RUN_TESTS_FILE="$LTP_ROOT/runtest/syscalls"

# need to stand here to run..
cd "$LTP_ROOT/testcases/bin"

grep . $RUN_TESTS_FILE | grep -v '#' | grep -vE 'msgstress0[1-4]' | sed -E 's/\s+/ /g' | while read L; do
	name="$(echo $L | cut -d' ' -f1).txt"
	cmdline="./$(echo $L | cut -d' ' -f2-)"
	echo "$name..."
	$FUNCGRAP_PATH -o "$ROUND_PATH/out/$name" -t $FGTRACE_PATH "$cmdline"
done
