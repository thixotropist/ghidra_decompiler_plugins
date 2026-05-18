CC:=/opt/riscv/sysroot/bin/riscv64-linux-gnu-gcc
MARCH:=rv64gcvzcb_zba


GET_NEXT_ARG_SRCS:= get_next_arg_test_1.S get_next_arg_test_2.S get_next_arg_test_3.S
GET_NEXT_ARG_OBJS= $(patsubst %.S, %.o, $(GET_NEXT_ARG_SRCS))

.PHONY: clean all

all: $(GET_NEXT_ARG_OBJS)

clean:
	@$(foreach file, $(GET_NEXT_ARG_OBJS),  rm $(file);)

%.o:%.S
	$(CC) -march=$(MARCH) -o $@ -c $<

%.so:%.S
	$(CC) -march=$(MARCH) -o $@ -c $<
