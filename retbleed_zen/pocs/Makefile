# SPDX-License-Identifier: GPL-3.0-only
CC = clang
CFLAGS = -O3

all: ret_bti cp_bti

ret_bti: ./ret_bti.c ./common.h
	$(CC) $(CFLAGS) -o $@ $<

cp_bti: ./cp_bti.c ./common.h
	$(CC) $(CFLAGS) -o $@ $<

eval_bw: ./eval_bw.c ./common.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm  -f ret_bti cp_bti eval_bw
