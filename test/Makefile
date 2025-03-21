CC:=/opt/riscv/sysroot/bin/riscv64-unknown-linux-gnu-g++

memcpy_exemplars.so: memcpy_exemplars.S
	$(CC) -march=rv64gcv -o $@ -c $<