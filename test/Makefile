CC:=/opt/riscv/sysroot/bin/riscv64-linux-gnu-gcc

memcpy_exemplars.so: memcpy_exemplars.S
	$(CC) -march=rv64gcv -o $@ -c $<

strlen_exemplars.so: strlen_exemplars.S
	$(CC) -march=rv64gcv -o $@ -c $<

dpdk_sample_2.so: dpdk_sample_2.S
	$(CC) -march=rv64gcv -o $@ -c $<

whisperInit.so: whisperInit.S
	$(CC) -march=rv64gcv -o $@ -c $<
