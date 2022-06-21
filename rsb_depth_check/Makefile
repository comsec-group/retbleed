CC := clang
OBJS := pmu.o
CFLAGS += -O0

ret_chain: ret_chain.c ${OBJS}
	$(CC) ${CFLAGS} -o $@ $< ${OBJS}

all: ret_chain

.PHONY:
clean:
	rm -f  ret_chain ${OBJS}
