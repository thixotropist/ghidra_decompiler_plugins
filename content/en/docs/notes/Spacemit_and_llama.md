---
title: Spacemit's code for accelerating AI RISC-V applications
description: Spacemit has contributed extensive RISC-V library accelerators for the AI Llama library.
weight: 200
---

The `whisper.cpp` voice to text app uses the GGML and Llama libraries for most of the
mathematics.  [SpacemiT](https://en.wikipedia.org/wiki/SpacemiT) has contributed about
[12K lines](https://github.com/ggml-org/llama.cpp/tree/master/ggml/src/ggml-cpu/spacemit) of code to accelerate these operations
on their processor line, with the
[SpacemiT K3](https://www.cnx-software.com/2026/01/23/spacemit-k3-16-core-risc-v-soc-system-information-and-early-benchmarks/)
processor a recent exemplar.  The GGML library contributions include non-standard RISC-V matrix operations as well as RVA23 standards
like the vector extensions we are considering here.

* The RISC-V optimizations are coded with RISC-V C intrinsics
* The optimizations are likely tuned for the 8 A100 cores on the K3, each with a VLEN of 1000 bits.
  The K3 also includes 8 X100 cores with VLEN of 256 bits for general purpose computing.
* Included benchmarks appear to focus on Q4_0 and Q4_1 quantization models, with 4 bits per weight.
  These two quantization schemes appear to be recommended for CPU-based (versus GPU-based) computations.

The Llama library code for CPU-based inference includes both vendor-independent RISC-V code and SpacemiT-optimized RISC-V code.

The current recommended build for SpacemiT K3 appears to be:

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DGGML_CPU_RISCV64_SPACEMIT=ON \
    -DGGML_CPU_REPACK=OFF \
    -DLLAMA_OPENSSL=OFF \
    -DGGML_RVV=ON \
    -DGGML_RV_ZVFH=ON \
    -DGGML_RV_ZFH=ON \
    -DGGML_RV_ZICBOP=ON \
    -DGGML_RV_ZIHINTPAUSE=ON \
    -DGGML_RV_ZBA=ON \
    -DCMAKE_TOOLCHAIN_FILE=${PWD}/cmake/riscv64-spacemit-linux-gnu-gcc.cmake \
    -DCMAKE_INSTALL_PREFIX=build/installed

cmake --build build --parallel $(nproc) --config Release
```

* The most customized SpacemiT source files used with `GGML_RVV` are `ggml/src/ggml-cpu/vec.*`.  These
  include a mix of riscv instrinsic C functions and riscv assembly statements.  This code includes functions tuned
  for the X100 and A100 core vector processing components.  Tuning includes selective loop unrolling and `LMUL=8` vector register grouping.
  The function `memcpy1d` defined in `ggml/src/ggml-cpu/spacemit/rvv_kernels.cpp` is a good example, using `LMUL=8` and a four-way loop unrolling
  if executing on an X100 core but `LMUL=8` and a two-way loop unrolling if executing on an A100 core.  Curiously, the vector setup uses `tu, mu` instead
  of `ta, ma`.
* The less customized RISC-V source files depend on the vector instructions being present but do not involve SpacemiT tuning.  For example,
  the `ggml_vec_dot_q4_1_q8_1` function defined in `ggml/src/ggml-cpu/arch/riscv/quants.c` implements a vector dot product between a vector of Q4_1 weights
  and a vector of Q8_1 values, returning a 322 bit float result.  There is no explicit LMUL or loop unrolling here.
