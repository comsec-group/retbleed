# SPDX-License-Identifier: GPL-3.0-only
CFLAGS := -O0

SOURCES := $(wildcard *.c)

paths := $(patsubst %.c,bin/%,$(SOURCES))

all: $(paths)

clean:
	rm -f bin/*

$(paths): bin/%: %.c
	$(CC) $(CFLAGS) -o $@ $<

