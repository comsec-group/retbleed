# SPDX-License-Identifier: GPL-3.0-only
CC = clang
CFLAGS = -O3

all: cp_bti

cp_bti: ./cp_bti.c ./common.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm  -f cp_bti
