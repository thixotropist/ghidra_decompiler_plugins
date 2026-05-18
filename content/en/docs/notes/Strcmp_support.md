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

The decompiler renders this vector sequence as:

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

## Implementing the transform

The assembly language `strcmp` exemplar presents as this Pcode after all transforms are taken:

```text
Basic Block 1 0x00100002-0x00100026
0x00100002:21:	a1(0x00100002:21) = a1(i) ? a1(0x0010000c:6)
0x00100002:20:	a0(0x00100002:20) = a0(i) ? a0(0x00100006:3)
0x00100002:2:	a2(0x00100002:2) = vsetvli_e8m1tama(#0x0)
0x00100006:3:	a0(0x00100006:3) = a0(0x00100002:20) + a2(0x00100002:2)(*#0x1)
0x00100008:5:	v1(0x00100008:5) = vle8ff_v(a0(0x00100006:3))
0x0010000c:6:	a1(0x0010000c:6) = a1(0x00100002:21) + a2(0x00100002:2)(*#0x1)
0x0010000e:8:	v2(0x0010000e:8) = vle8ff_v(a1(0x0010000c:6))
0x00100012:9:	v2(0x00100012:9) = vmsne_vv(v1(0x00100008:5),v2(0x0010000e:8))
0x00100016:b:	v1(0x00100016:b) = vmseq_vi(v1(0x00100008:5),#0x0)
0x0010001e:d:	v1(0x0010001e:d) = vmor_mm(v1(0x00100016:b),v2(0x00100012:9))
0x00100022:e:	t0(0x00100022:e) = vfirst_m(v1(0x0010001e:d))
0x00100026:f:	u0x00004100:1(0x00100026:f) = t0(0x00100022:e) < #0x0
0x00100026:10:	goto Block_1:0x00100002 if (u0x00004100:1(0x00100026:f) != 0) else Block_2:0x0010002a
Basic Block 2 0x0010002a-0x00100034
0x0010002a:11:	a0(0x0010002a:11) = a0(0x00100006:3) + t0(0x00100022:e)(*#0x1)
0x0010002c:12:	a1(0x0010002c:12) = a1(0x0010000c:6) + t0(0x00100022:e)(*#0x1)
0x0010002e:15:	u0x0008ac00:1(0x0010002e:15) = *(ram,a0(0x0010002a:11))
0x0010002e:26:	u0x10000008:1(0x0010002e:26) = (cast) u0x0008ac00:1(0x0010002e:15)
0x0010002e:16:	a0(0x0010002e:16) = ZEXT18(u0x10000008:1(0x0010002e:26))
0x00100030:19:	u0x0008ac00:1(0x00100030:19) = *(ram,a1(0x0010002c:12))
0x00100030:27:	u0x10000009:1(0x00100030:27) = (cast) u0x0008ac00:1(0x00100030:19)
0x00100030:1a:	a2(0x00100030:1a) = ZEXT18(u0x10000009:1(0x00100030:27))
0x00100032:1b:	a0(0x00100032:1b) = a0(0x0010002e:16) - a2(0x00100030:1a)
```

>Warning: This is the *final* pcode representation.  The transform code will see this
> as well as various intermediate representations which may not exactly match the expected pattern.
> If the code is traced, the log file may show one or more aborted transforms before the final
> successful transform.

We want it to transform into something like `a0(0x00100032:1b) = vector_strcmp(a0(i), a1(i))`.
The challenge is to do this in a way that is easily generalized to variant forms of `strcmp`.

The analysis methods have identified the two vector load operands and their loop register varnodes
as `v1(0x00100008:5)` and `v2(0x0010000e:8)`.  We want to:
* use the Phi node analysis to generate their external base Varnodes as `a0(i)` and `a1(i)` respectively.
* trace descendents of the operands to find common Varnodes:
    * `v1(0x00100008:5)`⇒(`v2(0x00100012:9)`, `v1(0x00100016:b)`)
    * `v2(0x0010000e:8)`⇒`v2(0x00100012:9)`⇒`v1(0x0010001e:d)`
    * `v1(0x00100016:b)`⇒`v1(0x0010001e:d)`
    * `v1(0x0010001e:d)`⇒`t0(0x00100022:e)`⇒(`u0x00004100:1(0x00100026:f)`, `a0(0x0010002a:11)`, `a1(0x0010002c:12)`)
    * `u0x00004100:1(0x00100026:f)`⇒`goto Block_1:0x00100002`
    * `a0(0x0010002a:11)`⇒`u0x0008ac00:1(0x0010002e:15)`⇒`u0x10000008:1(0x0010002e:26)`⇒`a0(0x0010002e:16)`⇒`a0(0x00100032:1b)`
    * `a1(0x0010002c:12)`⇒`u0x0008ac00:1(0x00100030:19)`⇒`u0x10000009:1(0x00100030:27)`⇒`a2(0x00100030:1a)`⇒`a0(0x00100032:1b)`

We want transform logic that identifies the Varnode `a0(0x00100032:1b)` without getting confused by ordering or casting.
We also need to know the relative ordering of `a0(0x0010002e:16)` and `a2(0x00100030:1a)` in the subtraction PcodeOp in order
to get the ordering of `a0(i)` and `a1(i)` correct.

`t0(0x00100022:e)` is already identified as the loop control Varnode, so the result PcodeOp we want is found by following the descendents
of the *register* dependencies of `t0(0x00100022:e)`, skipping internal or intermediate non-register dependencies, to find the common
descendent `a0(0x00100032:1b) = a0(0x0010002e:16) - a2(0x00100030:1a)`.

After some experimenting, we have a method for identifying the common descendent `a0(0x00100032:1b) = a0(0x0010002e:16) - a2(0x00100030:1a)`.

1. Trace the descendents of the pRegister varnodes of both source operands, excluding descendents of `t0(0x00100022:e)`
    1. a0(0x00100006:3) ⇒ v1(0x00100008:5), a0(0x00100002:20), a0(0x0010002a:11), a0(0x0010002e:16), \
                           a0(0x00100032:1b), a0(0x00100006:3), v2(0x00100012:9), v1(0x00100016:b), v1(0x0010001e:d)
    2. a1(0x0010000c:6) ⇒ v2(0x0010000e:8), a1(0x00100002:21), a1(0x0010002c:12), a2(0x00100030:1a), \
                           a0(0x00100032:1b), a1(0x0010000c:6), v2(0x00100012:9)
2. Find the intersection of these two sets: `[a0(0x00100032:1b), v2(0x00100012:9)]`
    1. Ignore the varnode resulting from the `vmsne_vv` instruction found within the loop block
    2. The result varnode is the one whose PcodeOp is a subtraction found within the epilog block

Add code to perform a minimal transform, not yet removing old code or fully integrating the result.

Now the pcode dumps as:

```text
Basic Block 0 0x00100000-0x00100000
0x00100000:27:	u0x10000008(0x00100000:27) = a0(i)
0x00100000:28:	u0x10000010(0x00100000:28) = a1(i)
Basic Block 1 0x00100002-0x00100026
0x00100002:21:	a1(0x00100002:21) = u0x10000010(0x00100000:28) ? a1(0x0010000c:6)
0x00100002:20:	a0(0x00100002:20) = u0x10000008(0x00100000:27) ? a0(0x00100006:3)
0x00100002:2:	a2(0x00100002:2) = vsetvli_e8m1tama(#0x0)
0x00100006:3:	a0(0x00100006:3) = a0(0x00100002:20) + a2(0x00100002:2)(*#0x1)
0x00100008:5:	v1(0x00100008:5) = vle8ff_v(a0(0x00100006:3))
0x0010000c:6:	a1(0x0010000c:6) = a1(0x00100002:21) + a2(0x00100002:2)(*#0x1)
0x0010000e:8:	v2(0x0010000e:8) = vle8ff_v(a1(0x0010000c:6))
0x00100012:9:	v2(0x00100012:9) = vmsne_vv(v1(0x00100008:5),v2(0x0010000e:8))
0x00100016:b:	v1(0x00100016:b) = vmseq_vi(v1(0x00100008:5),#0x0)
0x0010001e:d:	v1(0x0010001e:d) = vmor_mm(v1(0x00100016:b),v2(0x00100012:9))
0x00100022:e:	t0(0x00100022:e) = vfirst_m(v1(0x0010001e:d))
0x00100026:f:	u0x00004100:1(0x00100026:f) = t0(0x00100022:e) < #0x0
0x00100026:29:	u0x10000018(0x00100026:29) = (cast) a0(i)
0x00100026:2a:	u0x10000020(0x00100026:2a) = (cast) a1(i)
0x00100026:26:	a0(0x00100026:26) = vector_strcmp(u0x10000018(0x00100026:29),u0x10000020(0x00100026:2a))
0x00100026:10:	goto Block_1:0x00100002 if (u0x00004100:1(0x00100026:f) != 0) else Block_2:0x0010002a
Basic Block 2 0x0010002a-0x00100034
0x0010002a:11:	a0(0x0010002a:11) = a0(0x00100006:3) + t0(0x00100022:e)(*#0x1)
0x0010002c:12:	a1(0x0010002c:12) = a1(0x0010000c:6) + t0(0x00100022:e)(*#0x1)
0x0010002e:15:	u0x0008ac00:1(0x0010002e:15) = *(ram,a0(0x0010002a:11))
0x0010002e:2b:	u0x10000028:1(0x0010002e:2b) = (cast) u0x0008ac00:1(0x0010002e:15)
0x0010002e:16:	a0(0x0010002e:16) = ZEXT18(u0x10000028:1(0x0010002e:2b))
0x00100030:19:	u0x0008ac00:1(0x00100030:19) = *(ram,a1(0x0010002c:12))
0x00100030:2c:	u0x10000029:1(0x00100030:2c) = (cast) u0x0008ac00:1(0x00100030:19)
0x00100030:1a:	a2(0x00100030:1a) = ZEXT18(u0x10000029:1(0x00100030:2c))
0x00100032:1b:	a0(0x00100032:1b) = a0(0x0010002e:16) - a2(0x00100030:1a)
0x00100034:1c:	return(#0x0) a0(0x00100032:1b)
```

The next step is to search for uses of the result `a0(0x00100032:1b)` and replace with `a0(0x00100026:26)`,
then delete unused Varnode results.

After some wholesale code duplication from the `strlen` transform, we now get:

```c
long strcmp_base(char *s1,char *s2)

{
  undefined8 uVar1;
  uVar1 = vector_strcmp((char *)s1,(char *)s2);
  return uVar1;
}
```

```text
[decomp]> print raw
0
Basic Block 0 0x00100000-0x00100000
Basic Block 1 0x00100002-0x00100026
0x00100026:27:	u0x10000008(0x00100026:27) = (cast) a0(i)
0x00100026:28:	u0x10000010(0x00100026:28) = (cast) a1(i)
0x00100026:26:	a0(0x00100026:26) = vector_strcmp(u0x10000008(0x00100026:27),u0x10000010(0x00100026:28))
Basic Block 2 0x0010002a-0x00100034
0x00100034:1c:	return(#0x0) a0(0x00100026:26)
```

Now we have several next steps:

1. [x] build `strcmpeq` and `strncmpeq` assembly exemplars to test transforms of the more common case of testing for equality
   rather than ordering
2. [x] extend the existing transform code to handle `vector_strcmpeq`, probably in the same transform function as we use for `vector_strcmp`.
   We will still defer the transform of `vector_strncmpeq` until we get multiblock loops in hand.
3. [ ] find a way to refactor and reduce duplicate code

The minimalist `strcmpeq` assembly exemplar now decompiles as:

```c
bool strcmpeq(char *s1,char *s2)
{
  undefined1 uVar1;
  uVar1 = (undefined1)vector_strcmpeq((char *)s1,(char *)s2);
  if ((bool)uVar1) {
    return false;
  }
  return true;
}
```

That's good enough for now.

## Testing the transform

Next we need to apply this draft transform code to the `whisper.cpp` binary
1. Are most of the candidate strcmp transforms completed?
2. Are there exceptions thrown when attempting those transforms?
3. Is the logic correct, or have we more adjustments to make in handling strcmp results?
4. Should we accumulate more test cases abstracted from the `whisper.cpp` binary?

### Full decompilation

On the first attempt, we get 23 completed transforms and one exceptions.  The survey code suggests
that there are 24 potential `vector_strcmp` transforms present.

```text
Cause: Exception while decompiling ram:000c2dc2: Decompiler process died     //whisper_process_logits
```

Let's start by turning `gguf_find_key` into a test case `whisper_sample_11`.

The original source code is

```c
int64_t gguf_find_key(const struct gguf_context * ctx, const char * key) {
    // return -1 if key not found
    int64_t keyfound = -1;
    const int64_t n_kv = gguf_get_n_kv(ctx);
    for (int64_t i = 0; i < n_kv; ++i) {
        if (strcmp(key, gguf_get_key(ctx, i)) == 0) {
            keyfound = i;
            break;
        }
    }
    return keyfound;
}
```

The decompiler plugin currently gives us:

```c
long gguf_find_key(astruct *param_1,long param_2)

{
  undefined1 uVar1;
  long lVar2;
  long lVar3;
  char *lVar4;
  gp = &__global_pointer$;
  lVar3 = gguf_get_n_kv(param_1);
  if (0 < lVar3) {
    lVar2 = 0;
    do {
      lVar4 = gguf_get_key(param_1,lVar2);
      uVar1 = (undefined1)vector_strcmp((char *)param_2,(char *)lVar4);
      if ((bool)uVar1) {
        return lVar2;
      }
      lVar2 = (long)((int)lVar2 + 1);
    } while (lVar3 != lVar2);
  }
  return -1;
}
```

That's not correct:
* `uVar1` should be a long int, not undefined
* the test should read more like `if (uVar1 != 0) return lVar2;`

The solution depends on the context in which return value of `vector_strcmp` is generated and then used.

If the context is boolean, as in `std::string::operator==`, the `vector_strcmp` result is encapsulated in
a test:
* if the test looks like `s1[i] != s2[i]` then the vector result should be complemented as `!(s1[i] != s2[i])`, thus `true` if the strings
are equal.
* if the test looks like `s1[i] == s2[i]` then the vector result should remain `s1[i] == s2[i]`

Add this adjustment and repeat the `gguf_find_key` test:

```c
long gguf_find_key(void *s1,char *s2)
{
undefined1 uVar1;
long i;
long lVar2;
char *pcVar3;
lVar2 = gguf_get_n_kv(s1);
if (0 < lVar2) {
  i = 0;
  do {
    pcVar3 = gguf_get_key(s1,i);
    uVar1 = (undefined1)vector_strcmp((char *)s2,(char *)pcVar3);
    if (!(bool)uVar1) {
      return i;
    }
    i = (long)((int)i + 1);
  } while (lVar2 != i);
}
return -1;
}
```

At this point we find 23 strcmp transforms in whisper.cpp and one decompiler exception.  The decompiler exception occurs in function
`whisper_process_logits` at 0x000c2dc2, which we should turn into a new test case `whisper_sample_12`.

Running this new test case through valgrind exposes two problems, now fixed:
* result dependency calculations can get confused when those results are merged with other code in the epilog.  Add a test for a null `resultVarnode`
  and abandon that transform with a warning
* a memory leak occured when unexpected Ghidra ops were encountered.  Add supporting code to `VectorLoop::~VectorLoop`.

Finish by adding `whisper_sample_11` and `whisper_sample_12` to the integration test suite.

## Refactoring the transforms

The `vector_strcmp` transform is the most complex so far - does that mean we can consider the other loop transforms
simpler cases of `vector_strcmp`?  That would offer some refactoring opportunities and reduction in duplicated code - especially
duplicated tracing code.