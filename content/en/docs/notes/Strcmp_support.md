---
title: Adding support for vector_strcmp transforms
description: Given a vector_strlen transform, how much effort is adding a vector_strcmp transform?
weight: 90
---

Survey work suggests that support for vectorized `strcmp` sequences should be added next.  Our current framework
supports `vector_memcpy` and `vector_strlen` - does that make `vector_strcmp` support easy?

## Finding examples

First we need to find some examples, preferably in the wild rather than purely artificial.  Vectorized `strcmp`
sequences show up in the survey as having two `vle8ff.v` instructions within the vector loop.  Search `whisper.cpp`
to find an example.

```text
LAB_ram_000484b6:
 0484b6  vsetvli  a2,zero,e8,m1,ta,ma
 0484ba  c.add    a5,a3
 0484bc  vle8ff.v v1,(a5)
 0484c0  c.add    a4,a3
 0484c2  vle8ff.v v2,(a4)
 0484c6  vmsne.vv v2,v1,v2
 0484ca  vmseq.vi v1,v1,0x0
 0484ce  csrr     a3,vl
 0484d2  vmor.mm  v1,v1,v2
 0484d6  vfirst.m a1,v1
 0484da  blt      a1,zero,LAB_ram_000484b6
 0484de  c.add    a5,a1
 0484e0  c.add    a4,a1
 0484e2  c.lbu    a3,0x0(a5)
 0484e4  c.lbu    a5,0x0(a4)
 0484e6  bne      a3,a5,LAB_ram_000485a0
```

Without the vector transform, these are decompiled as:

```c
pcVar10 = _~regex_error + (*_~regex_error == '*');
lVar12 = 0;
do {
  vsetvli_e8m1tama(0);
  pcVar15 = pcVar15 + lVar12;
  auVar31 = vle8ff_v(pcVar15);
  pcVar10 = pcVar10 + lVar12;
  auVar32 = vle8ff_v(pcVar10);
  auVar32 = vmsne_vv(auVar31,auVar32);
  auVar31 = vmseq_vi(auVar31,0);
  auVar31 = vmor_mm(auVar31,auVar32);
  lVar26 = vfirst_m(auVar31);
  lVar12 = _vl;
} while (lVar26 < 0);
if (pcVar15[lVar26] == pcVar10[lVar26]) goto LAB_ram_000484ea;
```

The survey report for this stanza is:

```text
Vector Loop:
        Loop start address: 0x484b6
        Loop length: 0x24
        setvli mode: element size=0x1, multiplier=1, vector load register: 0x0, vector store register: 0x0
        vector loads: 0x2
        vector stores: 0x0
        comparisons: 0x1
        integer arithmetic ops: 2
        edges in: 1
        Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmseq_vi, vfirst_m, | vmsne_vv, vmor_mm, | +, +, ?,
        Loop control variable: a1(0x000484d6:23c) = vfirst_m(v1(0x000484d2:23b))
```

Observations:

* The loop compares elements of the two strings until either the elements don't match or at least one of the two elements is the null byte.
* Two new vector operations need to be recognized, `vmsne_vv` and `vmor_mm`.
* The `comparisons` survey field might be better split into `integer comparisons` and `vector comparisons`
* The three vector logical operations, `vmseq_vi`, `vmsne_vv`, and `vmor_mm` should probably be summed into a new survey report field, `vector logical operations`
* The epilog code compares the last tested element of both strings to determine the scalar result
    * if they are equal the loop terminated on hitting two null bytes and the strings match.
    * if they are not equal the loop terminated on a mismatch
* The invoking code only cares about equality, not resolving relative order.  A different epilog would be generated in different contexts, where the `strcmp` function
  is expected to return zero, a positive integer, or a negative integer.  We may need two different typed functions here, one returning a boolean and one an integer.
  The integer might be the difference between the last bytes.
* The source code generating this sequence appears to be from `stdlib::regex`, specifically the regex compiler invoking `std::sort` and `std::uniq`.  In these contexts
  the natural replacement function might be `operator<` and `operator==` respectively.

This suggests our `strcmp` example raises some design questions we hoped to put off until later - how to best represent more complicated semantics.

The next steps are:

* an informal search of `strcmp` instances
* explicitly handling the `vmsne_vv` and `vmor_mm` vector operations
* extending the survey report as noted above
* adding a `strcmp.S` test case

Other `whisper.cpp` locations of a likely `vector_strcmp`:
* 0x438a6
* 0x48cd4
* 0x495d0
* 0x4ebc2
* 0x51ec2
* 0x6b5e4
* 0x723fe

Some of these are within `std:regex` while others are found in functions like
`ggml_graph_get_tensor`.  The strong majority test only for equality, not ordering.

The `dpdk-pipeline` binary shows other examples, including a possible `strncmp` at 0xfc874.

```text
0fc866    c.mv     a2,s2
0fc868    c.li     a1,0x9
0fc86a    auipc    a3,0x8be
0fc86e    addi     a3,a3,0x73e
0fc872    c.li     a5,0x0
LAB_ram_000fc874:
0fc874    vsetvli  zero,a1,e8,m1,ta,ma
0fc878    c.add    a2,a5
0fc87a    vle8ff.v v1,(a2)
0fc87e    c.add    a3,a5
0fc880    vle8ff.v v3,(a3)
0fc884    csrr     a5,vl
0fc888    vmseq.vi v2,v1,0x0
0fc88c    vmsne.vv v1,v1,v3
0fc890    c.beqz   a5,LAB_ram_000fc8fe
0fc892    vmor.mm  v1,v2,v1
0fc896    c.sub    a1,a5
0fc898    vfirst.m a0,v1
0fc89c    blt      a0,zero,LAB_ram_000fc874
0fc8a0    c.add    a2,a0
0fc8a2    c.add    a3,a0
0fc8a4    lbu      a2,0x0(a2)
0fc8a8    lbu      a5,0x0(a3=>s_dpaa_bus:_ram_009bafa8)
0fc8ac    beq      a2,a5,LAB_ram_000fc8fe
```

The decompiler shows:

```c
  lVar3 = 9;
  pcVar6 = "dpaa_bus:";
  lVar4 = param_1;
  lVar5 = 0;
  do {
    vsetvli_e8m1tama(lVar3);
    lVar4 = lVar4 + lVar5;
    auVar10 = vle8ff_v(lVar4);
    pcVar6 = pcVar6 + lVar5;
    auVar12 = vle8ff_v(pcVar6);
    auVar11 = vmseq_vi(auVar10,0);
    auVar10 = vmsne_vv(auVar10,auVar12);
    if (vl == 0) goto LAB_ram_000fc8fe;
    auVar10 = vmor_mm(auVar11,auVar10);
    lVar3 = lVar3 - vl;
    lVar1 = vfirst_m(auVar10);
    lVar5 = vl;
  } while (lVar1 < 0);
  if (*(char *)(lVar4 + lVar1) == pcVar6[lVar1]) {
LAB_ram_000fc8fe:
    lVar4 = 9;
  }
```

The actual source code for this is:

```c
delta = 0;
if (strncmp(name, "dpaa_bus:", 9) == 0) {
        delta = 9;
} else if (strncmp(name, "name=", 5) == 0) {
        delta = 5;
}
```

That's odd for at least two reasons:

* The local variable lVar5 is set at the end of the loop, rather than after each of the `vle8_ff` instructions.
* The instruction ordering seems forced, possibly due to restart requirements after a page fault on either of the two vector load instructions.

Note that the `vl` register field is set up to three times in the loop:
1. when the vsetvli instruction decides how many vector elements to ask for
2. when the first vle8ff_v instruction decides whether a page boundary is crossed, possibly reducing the value of `vl`
3. when the second vle8ff_v instuction decides whether a page boundary is crossed, possibly further reducing the value of `vl`

The microarchitectural latencies *might* motivate odd instruction ordering.

## Generating test exemplars

The files are:

* `test/strcmp_exemplars.S` - the assembly source file holding both `strcmp` and `strncmp` exemplar functions.
* `test/strcmp_exemplars.so` - assemble and link the file with `MARCH=rv64gcvzcb`.
* `test/strcmp_exemplars_save.xml` - export the decompiler debug file, edited to include both function definitions
* `test/strcmp_exemplars.ghidra` - the decompiler test script to load both functions, print their PCodeOps and C decompilation.

The `test/strcmp_exemplars_save.xml` save file is a little different than other save files, as it includes function signatures
and some variable renaming.

## Extending the plugin survey and feature extraction.

The first issue is the failure of `VectorLoop::examine_control_flow` to recognize a loop
when it contains more than one conditional branch instruction, and therefore more than one
Block.  This breaks Survey when presented with a `vector_strncmp` sequence.

That makes a `vector_strncmp` transform fundamentally different than a `vector_strcmp` transform,
and something we will defer until after Survey finds a number of these in our executable
binaries.  The Survey code needs to be extended first on this path, perhaps recognizing
vector loops consisting of more than one Block.

The current Summary Report for a `strcmp` sequence is:

```text
Vector Loop (simple):
  control structure is simple
  Loop start address: 0x100002
  Loop length: 0x24
  setvli mode: element size=1, multiplier=1
  vector loads: 2
  vector stores: 0
  integer arithmetic ops: 2
  scalar comparisons: 1
  vector logical ops: 2
  vector integer ops: 0
  vector comparisons: 2
  vector source operands: 2
  vector destination operands: 0
  edges in: 1
  Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmsne_vv, vmseq_vi, vmor_mm, vfirst_m, | | +, +, ?,
  Loop control variable: t0(0x00100022:e) = vfirst_m(v1(0x0010001e:d))
```

For a `strncmp` sequence we now get:

```text
Vector Loop (complex):
  control structure is complex
  Loop start address: 0x100038
  Loop length: 0x1c
  setvli mode: element size=1, multiplier=1
  vector loads: 2
  vector stores: 0
  integer arithmetic ops: 2
  scalar comparisons: 1
  vector logical ops: 0
  vector integer ops: 0
  vector comparisons: 2
  vector source operands: 2
  vector destination operands: 0
  edges in: 2
  Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmsne_vv, vmseq_vi, | | vmor_mm, *, +, vfirst_m, <, ?,
```

Note:
* the 'Loop length' only reports the length of the first Block, up to the conditional branch testing the size parameter `n`.
* the second loop block is incorrectly identified as the 'epilog' block.
* two 'edges in' are reported, one being the prolog block and the other the conditional return to the first loop block.

The next steps on multiblock loop handling are:
* identify the 'edges in' blocks to find the second loop block.
* survey whisper and dpdk-pipeline to determine the frequency of multi-block loops.  This will likely include nested vector loops.

## Design choices

We may want two `vector_strcmp` variants, with one returning a boolean `true` on equality and the other a signed integer to indicate ordering.
The first may be named `vector_strcmpeq` while the second remains `vector_strcmp`.
