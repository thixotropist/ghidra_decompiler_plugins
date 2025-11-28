---
title: Methodology
weight: 80
---

We want a decompiler plugin that provides the Ghidra user a net gain in insight-per-hour.
In one extreme case, the plugin would be able to recognize and transform *any* RISC-V compiler vectorization into recognizable C or C++ source code.
Any transform completed is guaranteed to be correct, with no false-positive matches.
That's infeasible in the face of the variety of RISC-V extensions, compilers, and compiler optimization flags.
In another extreme case, vector stanza matching is very aggressive with minimal testing and a significant number of false-positive matches.
In this case the plugin code can be simpler but the human operator needs to check each transform they encounter.

Let's explore a case study applying Ghidra to a `whisper.cpp` RISC-V binary compiled with gcc 15 and the RVA23 profile.
We start with Ghidra 12-DEV and the `isa_ext` SLEIGH extensions, and a plugin capable of recognizing `vector_memcpy` sequences.
The user believes `vector_strlen` sequences are present along with other, more complicated vector sequences.
How do they spend their effort?
In this scenario, the user doesn't care about theoretical false-matches, only false-matches for *this* binary and *this* toolchain.

## initial survey - whisper.cpp

The user first explores the `whisper_cpp_rva23` binary with Ghidra but without plugin support.  They identify code
and basic library calls, and find perhaps 10% of the instructions present are vector instructions.
The decompiler window presents these instructions as something like:

```c
psVar36 = psVar19;
lVar17 = 0;
do {
    psVar36 = psVar36 + lVar17;
    vsetvli_e8m1tama(0);
    auVar48 = vle8ff_v(psVar36);
    auVar48 = vmseq_vi(auVar48,0);
    lVar18 = vfirst_m(auVar48);
    lVar17 = _vl;
} while (lVar18 < 0);
sVar8 = *psVar19;
psVar36 = psVar36 + (lVar18 - (long)psVar19) + 1;
```

The user recognizes this sequence as likely an inline vectorization of `psVar36 = strlen(psVar19)`.
* Is it worthwhile to extend the current Ghidra decompiler plugin to recognize this sequence and to replace
  the decompiler stanza with `psVar36 = vector_strlen(psVar19);`?
* Are there sequences present that resemble this sequence but should *not* be transformed?
* Are there other sequences present that are of higher priority to match and transform?

To start to answer these questions we need to survey the code for existing vector stanza loops, collecting
the sequence of vector instructions found within each Ghidra Block containing a `vsetvli*` instruction.
* Launch Ghidra with the current decompiler plugin
* Decompile all functions by exporting the binary as C or C++ to `whisper_cpp_rva23.c`
    * count the number of `vector_memcpy` transforms with `grep vector_memcpy whisper_cpp_rva23.c|wc`
* Collect survey results in `/tmp/riscv_summaries_*.txt`.  Note that Ghidra splits decompiler work across multiple processes,
  so we need to merge the per-process summary files into a single `/tmp/riscv_summaries.txt` instance
    * group and identify vector loops with similar vector instruction sequences with `grep handled riscv_summaries.txt|sort`

Initial results of the survey:

1307 vector loop stanzas were identified
* 906 appear to be `vector_memcpy` stanzas already recognized
* 90 appear to be `vector_strlen` stanzas
* 24 appear to be `strcmp` stanzas of one type or another
* 287 other stanzas were found, mostly of maybe 20 instances per type or fewer.

Two examples from the other stanzas:

```c
// FP multiply a vector by a scalar
do {
lVar10 = vsetvli_e32m1tama(uVar25);
auVar35 = vle32_v(pfVar13);
uVar25 = uVar25 - lVar10;
pfVar13 = pfVar13 + lVar10;
auVar35 = vfmul_vv(auVar35,auVar34);
vse32_v(auVar35,pfVar19);
pfVar19 = pfVar19 + lVar10;
} while (uVar25 != 0);
```

```c
// Z = aX + Y
vsetvli_e32m1tama(0);
auVar35 = vfmv_vf(uVar14);
do {
    lVar10 = vsetvli_e32m1tama(uVar25);
    auVar37 = vle32_v(pfVar13);   // load X
    auVar36 = vle32_v(pfVar26);   // load Y
    uVar25 = uVar25 - lVar10;
    pfVar13 = pfVar13 + lVar10;
    pfVar26 = pfVar26 + lVar10;
    auVar36 = vfmadd_vv(auVar35,auVar37,auVar36); // Z = aX + Y
    vse32_v(auVar36,pfVar19);     // store Z
    pfVar19 = pfVar19 + lVar10;
} while (uVar25 != 0);
```

Many of the remaining vector loops appear to be simple linear vector arithmetic operations, with one or two vector sources and a single vector
result.  That might provide some feature commonality to explore next.

One type of pattern is common but misleading: `vsetvli_e32mf2tuma, vle32_v, vmv1r_v, vfwadd_wv`.
This shows a vector load but no vector stores within the loop.  Ghidra inspection shows that this pattern is often a reduction operation,
with a sequence of vector operations often found immediately after the loop: `vsetvli_e64m1tama, vmv_s_x, vfredusum_vs, vfmv_fs`.
The `vfmv.f.s` instruction terminates this operation by moving a single element from a vector register into a scalar FP register.

With this survey *and this specific binary* the user's priorities are likely:
* Solidify recognition and transformation of `memcpy`, `strlen`, and `strcmp` sequences.
* Don't worry about false positives before finding a match.
* Don't worry about compiler unrolling loops with multiple loads and stores.
* Do consider common features of basic vector arithmetic transforms.
* Do consider exploring up to six instructions after a vector loop to identify reduction suffixes, especially when that vector loop contains no
  vector stores.

# initial survey - Dataplane Development Kit

The `whisper.cpp` binary is a good example of an inference engine application, something that uses a lot of vector math.  Repeat the survey
with a completely different type of binary, a Dataplane Development Kit network appliance.  This kind of binary will have little use for vector math
like inner products.  What kind of vector operations will it have instead?

## building the test binary

Checkout dpdk at version 25.11-rc4 and build with gcc 15.2 and arch_id = 'rv64gcv'.  Verify the build parameters first:

```console
$ readelf -A build_riscv64/examples/dpdk-pipeline
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_v1p0_zicsr2p0_zifencei2p0_zmmul1p0_zaamo1p0_zalrsc1p0_zca1p0_zcd1p0_zve32f1p0_zve32x1p0_zve64d1p0_zve64f1p0_zve64x1p0_zvl128b1p0_zvl32b1p0_zvl64b1p0"
  Tag_RISCV_priv_spec: 1
  Tag_RISCV_priv_spec_minor: 11
```

## surveying the dpdk binary

Load `dpdk-pipeline` into Ghidra which reports 2942862 instructions and 22999 functions found, with more than 10000 vset* instructions present.

>Note: exporting the entire binary as C results in three exceptions, in the functions at 0x2ab4c2, 0x6ffda2, and 0x83ef14.  These exceptions do not
>      occur when running Ghidra without a plugin.  More testing is needed here.

Examine the summaries to categorize on `Vector instructions` for a sense of common patterns.  There are about 5790 vector loops found in the survey

* 3495 likely `vector_memcpy` loops consisting of `vsetvli_e8m1tama, vle8_v, vse8_v,`
* 1202 likely `vector_strcmp` loops
* 300 likely `vector_strlen` loops
* 367 unrecognized loops involving `vsetvli_e8mf8tama, vle64_v, vse64_v`

The unrecognized loop structure *appears* to be a simple conversion from a vector of 8 bit elements to a vector of 64 bit elements.  This may
be a pattern worth capturing in the plugin.

## summary and path forward

The methodology is iterative, driven by the results in our two exemplar binaries.  The priorities are now:

* collect features for `vector_strcmp`
* complete the transforms for `vector_strlen`
* add collection of vector ops immediately following a vector loop without vector stores - looking for reduction stanzas.
* identify the root causes of the three dpdk exceptions
* add the dpdk and whisper binaries to the repo to better support regression testing
* consider adding basic vector math and type conversion operations to the transforms

Reduced priorities include:

* support for detecting loop unrolling
* support for complex vector loops
* additional detection of false positive matches
