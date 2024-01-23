# SPDX-License-Identifier: GPL-3.0-only
CC=gcc
mod-name := retbleed_poc
obj-m += $(mod-name).o
ccflags-y := \
	-O1 \
	-DDEBUG \
	-std=gnu99 \
	-Werror \
	$(CCFLAGS)
PWD=$(shell pwd)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

.PHONY:
install: all
	sudo insmod $(mod-name).ko

.PHONY:
remove:
	sudo rmmod $(mod-name).ko
