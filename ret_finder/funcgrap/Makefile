# SPDX-License-Identifier: GPL-3.0-only
CFLAGS += -O3
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Wpedantic
CC=clang

all: funcgrap

funcgrap: ./funcgrap.c
	$(CC) $(CFLAGS) -o $@ ./funcgrap.c
	sudo setcap CAP_SETUID=ep $@

