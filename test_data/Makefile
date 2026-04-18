CC:=/opt/riscv/sysroot/bin/riscv64-linux-gnu-gcc
MARCH:=rv64gcvzcb

%.so:%.S
	$(CC) -march=$(MARCH) -o $@ -c $<
