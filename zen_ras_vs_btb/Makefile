# SPDX-License-Identifier: GPL-3.0-only
CC      = clang
CFLAGS  = -O3
TARGET  = main


main: main.c common.h
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	-rm main
