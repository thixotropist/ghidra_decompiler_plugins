---
title: Walkthrough Examples
weight: 50
---

What does an early version of the RISC-V vector plugin actually do for us?  What more do we want it to do?  This page walks through
a couple of examples:

* The first is a synthetic collection of memcpy assembly routines in `test/memcpy_exemplars.S`.  This includes four fixed-length memcpy
  functions and one variable-length memcpy looping function.
* The second is a full `whisper-cpp` build using gcc 15 for RISC-V and a 64 bit rva23 machine architecture.  This is a complex example
  where the transforms need some work.

  ## memcpy_exemplars

The ghidra listing view shows us:

```text
**************************************************************
*                          FUNCTION                          *
**************************************************************
undefined memcpy_i2()
    vsetivli                       zero,0x2,e8,mf8,ta,ma 
    vle8.v                         v1,(a1)
    vse8.v                         v1,(a0)
    ret
```

The decompiler window shows this loop-free pattern has been transformed:

```c
void memcpy_i2(undefined8 param_1,undefined8 param_2)
{
  builtin_memcpy((void *)param_1,(void *)param_2,2);
  return;
}
```

The functions `memcpy_i4`, `memcpy_i8`, `memcpy_i15` show similar transforms,
recognizing the pattern even when unrelated instructions are interleaved
with the vector instructions.

The function `memcpy_v1` is more complex, since it involves a size parameter
rather than a size known at compile time.  Therefore a loop is present.

The Ghidra assembly view of `memcpy_v1` is:

```text
**************************************************************
*                          FUNCTION                          *
**************************************************************
void * __stdcall memcpy_v1(void * dest, void * src, int)
  a0:8           <RETURN>
  a0:8           dest
  a1:8           src
  a2:4           size
memcpy_v1                                       XREF[1]:     0010005a(j)  
    vsetvli                        a3,size,e8,m1,ta,ma  
    vle8.v                         v1,(src)
    c.sub                          size,a3
    c.add                          dest,a3
    vse8.v                         v1,(dest)
    c.add                          src,a3
    c.bnez                         size,memcpy_v1
    ret
```
The decompiler view shows that the transform has *not* been completed,
at least not with the inferred function signature.

```c
void * memcpy_v1(void *dest,void *src,int size)
{
  undefined4 in_register_00002064;
  long lVar1;
  long lVar2;
  undefined1 auVar3 [256];
  lVar1 = CONCAT44(in_register_00002064,size);
  do {
    lVar2 = vsetvli_e8m1tama(lVar1);
    auVar3 = vle8_v(src);
    lVar1 = lVar1 - lVar2;
    dest = (void *)((long)dest + lVar2);
    vse8_v(auVar3,dest);
    src = (void *)((long)src + lVar2);
  } while (lVar1 != 0);
  return dest;
}
```

There are two issues blocking the transform to `builtin_memcpy`.  The first is easy to fix, the second raises some design issues.

* The `CONCAT44` function is present because the size parameter is typed as a 4 byte `int`, while the `vsetvli`
  instruction expects an 8 byte `int`.  We can fix this by manually altering the signature to expect a `long long` type for `size`.
* The inferred function signature returns a `void*` object in register `a0`.  The `return` statement thus has a dependency on
  (aka is a *descendent* of) any pcodeop that modifies `a0`.  The existing `memcpy` transform heuristic fails if it finds an unexpected
  pcodeop as a descendent.  The `builtin_memcpy` function defined within Ghidra expects to return the *initial* destination address in `a0`,
  even if this is often ignored in common usage.  We can explicitly tell the decompiler ignores the a0 return by changing the return type
  from `void*` to `void`.

The analysis log gives more detail:

```text
Completed the descendent scan, finding these PcodeOps
 PcodeOp: a3(0x00100048:0) = vsetvli_e8m1tama(a2(0x00100048:f));        OpName: syscall;        Addr: 0x100048
 PcodeOp: a0(0x00100048:c) = a0(0x00100052:4) ? a0(i);  OpName: ?;      Addr: 0x100048
 PcodeOp: a1(0x00100048:d) = a1(0x00100058:7) ? a1(i);  OpName: ?;      Addr: 0x100048
 PcodeOp: a2(0x00100048:e) = CONCAT44(%0x00002064:4(i),a2:4(i));        OpName: CONCAT; Addr: 0x100048
 PcodeOp: a2(0x00100048:f) = a2(0x00100050:3) ? a2(0x00100048:e);       OpName: ?;      Addr: 0x100048
 PcodeOp: v1(0x0010004c:2) = vle8_v(a1(0x00100048:d));  OpName: syscall;        Addr: 0x10004c
 PcodeOp: a2(0x00100050:3) = a2(0x00100048:f) - a3(0x00100048:0);       OpName: -;      Addr: 0x100050
 PcodeOp: <null> = - <null>;    OpName: -;      Addr: 0x100050
 PcodeOp: a0(0x00100052:4) = a0(0x00100048:c) + a3(0x00100048:0);       OpName: +;      Addr: 0x100052
 PcodeOp: vse8_v(v1(0x0010004c:2),a0(0x00100052:4));    OpName: syscall;        Addr: 0x100054
 PcodeOp: a1(0x00100058:7) = a1(0x00100048:d) + a3(0x00100048:0);       OpName: +;      Addr: 0x100058
 PcodeOp: u0x00018500:1(0x0010005a:8) = a2(0x00100050:3) != #0x0;       OpName: !=;     Addr: 0x10005a
 PcodeOp: goto r0x00100048:1(free) if (u0x00018500:1(0x0010005a:8) != 0);       OpName: goto;   Addr: 0x10005a
 PcodeOp: return(#0x0) a0(0x00100052:4);        OpName: return; Addr: 0x10005c
Unexpected op found in analysis PcodeOp: a2(0x00100048:e) = CONCAT44(%0x00002064:4(i),a2:4(i)); OpName: CONCAT; Addr: 0x100048
Analysis:
        numPcodes = 14
        elementSize = 1
        multiplier = 1
        Length in Bytes = 20
        loopFound = 1
        simpleFlowStructure = 0
        simpleLoadStoreStructure = 1
        foundOtherUserPcodes = 0
        foundSimpleComparison = 1
        foundUnexpectedOp = 1
        numArithmeticOps = 3
        vectorRegistersMatch = 1
```
The transform failed because `simpleFlowStructure = false` and `foundUnexpectedOp = true`.

Edit the function signature, which forces a new decompile execution:

```c
void memcpy_v1(void *dest,void *src,longlong size)
{
  do {
    builtin_memcpy(dest,src,(int)size);
  } while ;
  return;
}
```
That's not perfect, but probably good enough for now.

The analysis log now shows:

```text
Completed the descendent scan, finding these PcodeOps
 PcodeOp: a3(0x00100048:0) = vsetvli_e8m1tama(a2(0x00100048:e));        OpName: syscall;        Addr: 0x100048
 PcodeOp: a0(0x00100048:c) = a0(0x00100052:4) ? a0(i);  OpName: ?;      Addr: 0x100048
 PcodeOp: a1(0x00100048:d) = a1(0x00100058:7) ? a1(i);  OpName: ?;      Addr: 0x100048
 PcodeOp: a2(0x00100048:e) = a2(0x00100050:3) ? a2(i);  OpName: ?;      Addr: 0x100048
 PcodeOp: v1(0x0010004c:2) = vle8_v(a1(0x00100048:d));  OpName: syscall;        Addr: 0x10004c
 PcodeOp: a2(0x00100050:3) = a2(0x00100048:e) + u0x10000000(0x00100050:11);     OpName: +;      Addr: 0x100050
 PcodeOp: u0x10000000(0x00100050:11) = a3(0x00100048:0) * #0xffffffffffffffff;  OpName: *;      Addr: 0x100050
 PcodeOp: a0(0x00100052:4) = a0(0x00100048:c) + a3(0x00100048:0);       OpName: +;      Addr: 0x100052
 PcodeOp: vse8_v(v1(0x0010004c:2),a0(0x00100052:4));    OpName: syscall;        Addr: 0x100054
 PcodeOp: a1(0x00100058:7) = a1(0x00100048:d) + a3(0x00100048:0);       OpName: +;      Addr: 0x100058
 PcodeOp: u0x00018500:1(0x0010005a:8) = a2(0x00100050:3) != #0x0;       OpName: !=;     Addr: 0x10005a
 PcodeOp: goto r0x00100048:1(free) if (u0x00018500:1(0x0010005a:8) != 0);       OpName: goto;   Addr: 0x10005a
Analysis:
        numPcodes = 12
        elementSize = 1
        multiplier = 1
        Length in Bytes = 18
        loopFound = 1
        simpleFlowStructure = 1
        simpleLoadStoreStructure = 1
        foundOtherUserPcodes = 0
        foundSimpleComparison = 1
        foundUnexpectedOp = 0
        numArithmeticOps = 3
        vectorRegistersMatch = 1
```

The `simpleFlowStructure = true` and `foundUnexpectedOp = false` flags allow the transform to complete.

The two remaining issues here are:

* The existing Ghidra `builtin_memcpy` function is a typed function, where the size parameter has been
  typed as `int`.  It should probably be typed as `size_t` or some other `int` with the architecture's wordsize.
* The decompiler leaves `builtin_memcpy` within an empty `do while` loop.  This is likely due to the transform
  deleting a `goto` operation, without merging the containing flow block into the subsequent flow block.  We don't
  know enough about Ghidra's decompiler block operations to safely merge those blocks.

## whisper-cpp

>Note: this section will change rapidly as issues surface and the transforms evolve

Open `whisper_cpp_rva23` and search for the first instance of a `vset*` instruction.  We're looking
for a general sense of priority changes to make.

The first example is a simple builtin_memset operation clearing a couple of 64 bit elements:

```text
vsetivli zero,0x2,e64,m1,ta,ma 
vmv.v.i  v1,0x0
addi     s3,gp,-0x7f0
li       a0,0xe0
vse64.v  v1,(s3)
sd       zero,-0x7e0(gp=>DAT_00143c58)                    = ??
```

The decompiler recognizes the pattern and transforms this with a couple of errors:

```c
vsetivli_e64m1tama(2);
auVar8 = vmv_v_i(0);
builtin_memset((void *)0x143c48,0,0x10);
builtin_memset((void *)0x143c48,0,0x10);
vse64_v(auVar8,0x143c48);
```
The `builtin_memset` invocation looks accurate but it is duplicated,
and the three vector instructions have not been deleted by the transform.
The duplication appears to be caused by the failure to delete the vector instructions,
so a new `builtin_memset` is created for each pass through the function.

Code inspection shows the problem - the search algorithm loop termination
conditions were faulty.

Make the correction, replace the plugin, close and reopen the `whisper_cpp` window.
Note that we do not have to exit Ghidra or replace the decompile program to rerun the test.

Now the decompiler window correctly shows:

```c
builtin_memset((void *)0x143c48,0,0x10);
```

The builtin_memset transform now occurs 249 times in whisper_cpp, *most* of which look
reasonable.

Some transforms are clearly wrong - it looks like the match code is failing to verify that
a given vector instruction is actually a vector store instruction before absorbing it into
a `builtin_memset`.
