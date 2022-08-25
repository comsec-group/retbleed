#!/bin/bash
make clean
make

EXP=$1
if [ -z "$EXP" ]; then
	echo Pass EXP
	exit 1
elif [ -f "./$EXP" ]; then
	echo $EXP exists.
	exit 1
fi

mkdir "./$EXP"
for x in {0..34}; do
	sudo ./ret_chain $x >> "./$EXP/ret.txt"
done

make clean
CFLAGS=-DUSE_JMP make
for x in {0..34}; do
	sudo ./ret_chain $x >> "./$EXP/jmp.txt"
done
