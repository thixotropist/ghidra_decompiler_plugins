---
title: Exemplars
description: Exemplars help frame design decisions and priorities
weight: 110
---

This project explores useful extensions to Ghidra's decompiler. Utility here is measured
as if the user is analyzing the latest generation of networking autonomous vehicles, each with
their own inference engine.  For that we need some exemplars:

* A current GCC cross-compiler toolchain for RISC-V 64bit cores implementing the RVA-23 profile.
* Exemplar binaries representing network and device driver code, currently drawn from the Data Plane
  Development Kit example set.
* Exemplar binaries representing basic AI and Inference Engine code, currently drawn from the
  Whisper-cpp voice to text example set.

## Building the exemplars

### DPDK exemplar

The first DPDK exemplar iteration used a GCC 15.2 toolchain with a machine architecture of `march=rv64gcv`.
That only covers a portion of the RISC-V RVA23 profile many upcoming cores support.  Let's rebuild
that exemplar to include support for the scalar bit manipulation instructions too.
That means we want to build with `march=rv64gcv_zba_zbb_zbc` instead, then see if these new
instructions materially change what we need from Ghidra.

1. Clone [DPDK](https://github.com/DPDK/dpdk.git), currently at tag v26.03
2. Add a new configuration cross-file `config/riscv/riscv64_rva23u64_linux_gcc`.  Using the existing
   `riscv64_rv64gcv_linux_gcc` as a base, edit the paths to match toolchain binaries on your system.
3. Edit `config/riscv/meson.build` to replace `-march=rv64gcv` with `-march=rv64gcv_zba_zbb_zbc`
4. Configure the build with `meson setup  build_riscv64_rva23 --cross-file config/riscv/riscv64_rva23u64_linux_gcc -Dexamples=all`
5. Edit `build_riscv64_rva23/build.ninja` to see if `march=rv64gcv_zba_zbb_zbc` is present everywhere.
   If not, replace `rv64gcv` with `rv64gcv_zba_zbb_zbc` in all 2000+ locations
6. Build libraries and example binaries with `ninja -C build_riscv64_rva23`
7. Pick `build_riscv64_rva23/examples/dpdk-l3fwd` as the exemplar binary to use, and examine the
   RISCV_arch tag:
    ```text
    $ readelf -A build_riscv64_rva23/examples/dpdk-l3fwd
    Attribute Section: riscv
    File Attributes
        Tag_RISCV_stack_align: 16-bytes
        Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_v1p0_zicsr2p0_zifencei2p0_zmmul1p0_zaamo1p0_zalrsc1p0_zca1p0_zcd1p0_zba1p0_zbb1p0_zbc1p0_zve32f1p0_zve32x1p0_zve64d1p0_zve64f1p0_zve64x1p0_zvl128b1p0_zvl32b1p0_zvl64b1p0"
        Tag_RISCV_priv_spec: 1
        Tag_RISCV_priv_spec_minor: 11
    ```
    That tag includes `v1p0`, `zba1p0`, `zbb1p0`, `zbc1p0`, so we know the compiler has enabled those four
    extensions.
8. Import the 18 MB binary into Ghidra and analyze it.  You should see about 2.91M instructions recognized.
9. Search the program text for instruction mnemonics containing `cpop`.  You should see about 960 matches,
   with about 875 being vector cpop instructions enabled by `v1p0` and 85 scalar `cpop` instructions
   enabled by `zbb1p0`.
