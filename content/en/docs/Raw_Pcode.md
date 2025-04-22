---
title: Raw Pcode Tutorial
weight: 30
---

>Note: This is a stub to be expanded with more examples and diagnostic probes of the objects supporting `printRaw` methods.
>      Understanding Indirect varnodes and varnode lifetime and references in the presence of simple loops is next on the TODO list.

Ghidra's Actions and transformation work at the pcode level.  The decompiler's console tool has a useful command `print raw`, which displays
a function's pcode representation after all rules have been applied and the pcode has stabilized.

Here's a very simple vector copy function in its original assembly source:

```as
.extern memcpy_i2
memcpy_i2:
    vsetivli zero,0x2,e8,mf8,ta,ma 
    vle8.v   v1,(a1)
    vse8.v   v1,(a0)
    ret
```

Ghidra's decompiler (without a vector-transform plugin) generates a C-like representation when given the binary for
this function, its signature, and the `print c` command:

```c
[decomp]> print C
void memcpy_i2(void *to,void *from,ulong size)
{
  undefined auVar1 [256];
  vsetivli_e8mf8tama(2);
  auVar1 = vle8_v(from);
  vse8_v(auVar1,to);
  return;
}
```

The raw pcode is available too (annotated with `//`)

```text
[decomp]> print raw
0
Basic Block 0 0x00000000-0x0000000c             // a basic block has no jumps in or out, except for the last op
0x00000000:1:	vsetivli_e8mf8tama(#0x2:5)        // no output varnode, a single input varnode of constant 0x2, in a 5 bit field
0x00000004:3:	v1(0x00000004:3) = vle8_v(a1(i))  // output varnode is v1(0x00000004:3), pcodeop is CALLOTHER, input varnode 0 is vle8_v,
                                                // input varnode 1 is register a1 (likely an indirect or input varnode)
0x00000008:5:	vse8_v(v1(0x00000004:3),a0(i))    // no output varnode, pcodeop is CALLOTHER, input varnode 0 is vle8_v,
                                                // input varnode 1 is register v1, input varnode 2 is register a0
0x0000000c:6:	return(#0x0)
```

Note that Varnodes like `v1(0x00000004:3)` include both the register name (`v1`) and the pcode location and sequence number
at which the register was set (`0x00000004:3`).
The `i` field likely means this is an Indirect or input varnode, in this case provided externally via a function call.

## Initialization blocks

Slice some instructions from the `Whisper.cpp` main routine to give a more complex - but still loop-free - example.

The assembly source code is:

```as
c.addi16sp sp,-0x160
vsetivli   zero,0x4,e32,m1,ta,ma 
vle32.v    v3,(a3)
auipc      a4,0xe7
addi       a4,a4,-0x65a
vsetivli   zero,0x2,e32,mf2,ta,ma
vle32.v    v2,(a4)
auipc      a5,0xe7
addi       a5,a5,-0x662
vsetivli   zero,0x8,e8,mf2,ta,ma 
vle8.v     v1,(a5)
lw         a5,-0x5f4(s0)
vsetivli   zero,0x10,e8,m1,ta,ma
vmv.v.i    v4,0x0
sw         a5,-0x27c(s0)
addi       a5,s0,-0x800
addi       a0,s0,-0x240
addi       a5,a5,-0xc8
c.sd       a0,0x0(a5)
addi       a5,s0,-0x258
vse8.v     v4,(a5)
auipc      a4,0xd9
flw        fa5,0x84(a4)
addi       a5,s0,-0x274
vsetivli   zero,0x4,e32,m1,ta,ma 
vse32.v    v3,(a5)
addi       a5,s0,-0x264
vsetivli   zero,0x2,e32,mf2,ta,ma
vse32.v    v2,(a5)
auipc      a1,0xdd
addi       a1,a1,-0x500
addi       a5,s0,-0x248
vsetivli   zero,0x8,e8,mf2,ta,ma 
vse8.v     v1,(a5)
sw         zero,-0x278(s0)
fsw        fa5,-0x25c(s0)
c.addi16sp sp,0x160
ret
```

Assemble this and give it to the decompiler:

```text
[decomp]> print C
long main(int argc,char *argv,void *allocator)
{
  undefined4 uVar1;
  long unaff_s0;
  undefined8 in_a3;
  undefined auVar2 [256];
  undefined auVar3 [256];
  undefined auVar4 [256];
  undefined auVar5 [256];
  
  vsetivli_e32m1tama(4);
  auVar4 = vle32_v(in_a3);
  vsetivli_e32mf2tama(2);
  auVar3 = vle32_v(0x1e69b0);
  vsetivli_e8mf2tama(8);
  auVar2 = vle8_v(0x1e69b8);
  vsetivli_e8m1tama(0x10);
  auVar5 = vmv_v_i(0);
  *(undefined4 *)(unaff_s0 + -0x27c) = *(undefined4 *)(unaff_s0 + -0x5f4);
  *(long *)(unaff_s0 + -0x8c8) = unaff_s0 + -0x240;
  uVar1 = uRam00000000001d90d4;
  vse8_v(auVar5,unaff_s0 + -600);
  vsetivli_e32m1tama(4);
  vse32_v(auVar4,unaff_s0 + -0x274);
  vsetivli_e32mf2tama(2);
  vse32_v(auVar3,unaff_s0 + -0x264);
  vsetivli_e8mf2tama(8);
  vse8_v(auVar2,unaff_s0 + -0x248);
  *(undefined4 *)(unaff_s0 + -0x278) = 0;
  *(undefined4 *)(unaff_s0 + -0x25c) = uVar1;
  return unaff_s0 + -0x240;
}
[decomp]> print raw
0
Basic Block 0 0x00100000-0x0010008e
0x00100002:3:	vsetivli_e32m1tama(#0x4:5)
0x00100006:5:	v3(0x00100006:5) = vle32_v(a3(i))
0x00100012:b:	vsetivli_e32mf2tama(#0x2:5)
0x00100016:d:	v2(0x00100016:d) = vle32_v(#0x1e69b0)
0x00100022:13:	vsetivli_e8mf2tama(#0x8:5)
0x00100026:15:	v1(0x00100026:15) = vle8_v(#0x1e69b8)
0x0010002a:17:	u0x10000004(0x0010002a:17) = s0(i) + #0xfffffffffffffa0c
0x0010002a:5f:	u0x00003280(0x0010002a:5f) = (cast) u0x10000004(0x0010002a:17)
0x0010002a:18:	u0x00003300:4(0x0010002a:18) = *(ram,u0x00003280(0x0010002a:5f))
0x0010002e:1b:	vsetivli_e8m1tama(#0x10:5)
0x00100032:1d:	v4(0x00100032:1d) = vmv_v_i(#0x0)
0x00100036:1f:	u0x1000000c(0x00100036:1f) = s0(i) + #0xfffffffffffffd84
0x00100036:60:	u0x00004380(0x00100036:60) = (cast) u0x1000000c(0x00100036:1f)
0x00100036:5a:	r0x001d90d4:4(0x00100036:5a) = r0x001d90d4:4(i) [] i0x00100036:20(free)
0x00100036:20:	*(ram,u0x00004380(0x00100036:60)) = u0x00003300:4(0x0010002a:18)
0x0010003e:24:	a0(0x0010003e:24) = s0(i) + #0xfffffffffffffdc0
0x00100042:26:	u0x10000014(0x00100042:26) = s0(i) + #0xfffffffffffff738
0x00100042:61:	a5(0x00100042:61) = (cast) u0x10000014(0x00100042:26)
0x00100046:5b:	r0x001d90d4:4(0x00100046:5b) = r0x001d90d4:4(0x00100036:5a) [] i0x00100046:29(free)
0x00100046:29:	*(ram,a5(0x00100042:61)) = a0(0x0010003e:24)
0x00100046:5e:	u0x10000000:4(0x00100046:5e) = r0x001d90d4:4(0x00100046:5b)
0x00100048:2b:	a5(0x00100048:2b) = s0(i) + #0xfffffffffffffda8
0x0010004c:2d:	vse8_v(v4(0x00100032:1d),a5(0x00100048:2b))
0x00100058:35:	a5(0x00100058:35) = s0(i) + #0xfffffffffffffd8c
0x0010005c:37:	vsetivli_e32m1tama(#0x4:5)
0x00100060:39:	vse32_v(v3(0x00100006:5),a5(0x00100058:35))
0x00100064:3b:	a5(0x00100064:3b) = s0(i) + #0xfffffffffffffd9c
0x00100068:3d:	vsetivli_e32mf2tama(#0x2:5)
0x0010006c:3f:	vse32_v(v2(0x00100016:d),a5(0x00100064:3b))
0x00100078:45:	a5(0x00100078:45) = s0(i) + #0xfffffffffffffdb8
0x0010007c:47:	vsetivli_e8mf2tama(#0x8:5)
0x00100080:49:	vse8_v(v1(0x00100026:15),a5(0x00100078:45))
0x00100084:4b:	u0x1000001c(0x00100084:4b) = s0(i) + #0xfffffffffffffd88
0x00100084:62:	u0x00004380(0x00100084:62) = (cast) u0x1000001c(0x00100084:4b)
0x00100084:5c:	r0x001d90d4:4(0x00100084:5c) = r0x001d90d4:4(0x00100046:5b) [] i0x00100084:4c(free)
0x00100084:4c:	*(ram,u0x00004380(0x00100084:62)) = #0x0:4
0x00100088:4f:	u0x10000024(0x00100088:4f) = s0(i) + #0xfffffffffffffda4
0x00100088:63:	u0x0000d800(0x00100088:63) = (cast) u0x10000024(0x00100088:4f)
0x00100088:5d:	r0x001d90d4:4(0x00100088:5d) = r0x001d90d4:4(0x00100084:5c) [] i0x00100088:50(free)
0x00100088:50:	*(ram,u0x0000d800(0x00100088:63)) = u0x10000000:4(0x00100046:5e)
0x0010008e:59:	r0x001d90d4:4(0x0010008e:59) = r0x001d90d4:4(0x00100088:5d)
0x0010008e:53:	return(#0x0) a0(0x0010003e:24)
```

How do we interpret these printRaw descriptions?
* the varnodes generally include a location of the `PcodeOp` at which they are generated
    * if the varnode is an input, such as a function parameter or register loaded before the block, you see `(i)`
    * if the varnode is generated in the function, you see something like `(0x00100006:5)`,
      where `0x00100006` is a memory address and `5` is sequence number.
* varnodes like `u0x1000001c(...)` appear to be temporaries of unknown type
    * the `u` character appears to be a shortcut for the `AddrSpace` of the varnode, as specified in
      `AddrSpaceManager::assignShortcut`.
    * `u` implies IPTR_INTERNAL. likely a temporary of known type, here of type `long*`.
    * `#` implies IPTR_CONSTANT
    * `%` implies IPTR_PROCESSOR or maybe `register`
    * `r` indicates a RAM address
    * `i` appears to indicate a store to RAM operation 
* varnodes like `r0x001d90d4:4(0x00100088:5d) = r0x001d90d4:4(0x00100084:5c) [] i0x00100088:50(free)`
  *appear* to indicate a RAM variable that may hold a pre-existing value or may be rewritten by the `i0x00100088:50` varnode
* note that some instructions have been deleted from this raw pcode listing - the floating point loads and stores
  for instance are gone.  Perhaps they were identified as dead code?

## Simple loops

This example starts with a common gcc utility `__builtin_memcpy`, often found when optimizing calls to the stdlib `memcpy` and in inline
copy constructors. If the number of bytes to copy is not known at compile time a simple loop is needed.  The emitted assembly can look like this:

```as
memcpy_v1:
    vsetvli  a3,a2,e8,m1,ta,ma
    vle8.v   v1,(a1)
    sub      a2,a2,a3
    c.add    a0,a3
    vse8.v   v1,(a0)
    c.add    a1,a3
    bne      a2,zero,memcpy_v1
    ret
```

Ghidra's standard decompiler renders this as:

```c
void memcpy_v1(void *to,void *from,ulong size)
{
  long lVar1;
  undefined auVar2 [256];
  do {
    lVar1 = vsetvli_e8m1tama(size);
    auVar2 = vle8_v(from);
    size = size - lVar1;
    to = (void *)((long)to + lVar1);
    vse8_v(auVar2,to);
    from = (void *)((long)from + lVar1);
  } while (size != 0);
  return;
}
```

The `print raw` decompiler console command shows this:

```text
Basic Block 0 0x00000048-0x00000048
Basic Block 1 0x00000048-0x0000005a
0x00000048:e:	a2(0x00000048:e) = a2(0x00000050:3) ? a2(i)
0x00000048:d:	a1(0x00000048:d) = a1(0x00000058:15) ? a1(i)
0x00000048:c:	a0(0x00000048:c) = a0(0x00000052:13) ? a0(i)
0x00000048:0:	a3(0x00000048:0) = vsetvli_e8m1tama(a2(0x00000048:e))
0x0000004c:2:	v1(0x0000004c:2) = vle8_v(a1(0x00000048:d))
0x00000050:3:	a2(0x00000050:3) = a2(0x00000048:e) - a3(0x00000048:0)
0x00000052:12:	u0x10000008(0x00000052:12) = (cast) a0(0x00000048:c)
0x00000052:4:	u0x10000010(0x00000052:4) = u0x10000008(0x00000052:12) + a3(0x00000048:0)
0x00000052:13:	a0(0x00000052:13) = (cast) u0x10000010(0x00000052:4)
0x00000054:6:	vse8_v(v1(0x0000004c:2),a0(0x00000052:13))
0x00000058:14:	u0x10000018(0x00000058:14) = (cast) a1(0x00000048:d)
0x00000058:7:	u0x10000020(0x00000058:7) = u0x10000018(0x00000058:14) + a3(0x00000048:0)
0x00000058:15:	a1(0x00000058:15) = (cast) u0x10000020(0x00000058:7)
0x0000005a:8:	u0x00018500:1(0x0000005a:8) = a2(0x00000050:3) != #0x0
0x0000005a:9:	goto r0x00000048:1(free) if (u0x00018500:1(0x0000005a:8) != 0)
Basic Block 2 0x0000005c-0x0000005c
0x0000005c:a:	return(#0x0)
```

Notes:

* the loop exists completely within Basic Block 1, terminating with a conditional branch to location 0x00000048.
* the loop begins with four pcodeops at a single address  0x00000048.
    * three of these are so-called Phi or MULTIEQUAL expressions, naming registers that have needed values
      on entry to the loop and are updated within the loop
    * one is the `vsetvli` instruction setting the vector context, invoked with a CALLOTHER (aka syscall) pcode operation.
      This operation identifies the `size` input varnode `a2(0x00000048:e)` and the number of elements processed per loop
      varnode `a2(0x00000050:3)`
    * these four pcodeops can occur in any order
* the vector load and store operations identify from and to pointer varnodes `a1(0x00000048:d)` and `a0(0x00000052:13`
  as well as the base vector register `v1`.
    * three `cast` pcode ops are present, perhaps added late in processing, to capture type operations.
* the conditional branch becomes a comparison operation and a conditional goto operation
* none of the registers (a0, a1, a2, v1) are used after the loop is complete.  In Ghidra terms, they have no descendents
  or readers.

Therefore these pcode ops could be replaced with a single pcode op - *if* we were sure there were no descendents.
We should also merge Basic Block 1 into Basic Block 2, as the branch instruction is to be absorbed.

```text 
0x00000048:XX builtin_memcpy(a0(i), a1(i), a2(i))
```

If this was a `builtin_memset` loop, we would likely see:
* a loop preamble consisting of a vset instruction and a vmv vector load immediate instruction
* the loop would no longer include a vector load or source pointer increment

### loop feature recognition

If we want to recognize this kind of loop and transform it into a `builtin_*` operation, a successive-refinement
strategy can be used.  The starting point will be a vsetvli instruction.

>TODO: update the following to match the final logic flow

1. Search the block forward for a conditional goto instruction terminating on or near the vsetvli instruction address.
   Save the loop address range and the vsetvli output varnode holding the number of elements processed per iteration.
2. Search the loop to locate a vector load and a vector store instruction.  Save the varnodes used as pointers, and assert
   that the same vector register is used in each.
3. Search for MULTIEQUAL/Phi opcodes at location of the vsetvli instruction, discarding any varnodes set inside the loop
   and assigning varnodes set outside of the loop as `to`, `from`, and `size` varnodes to the builtin_memset we will form.
4. Perform other sanity checks to rule out more complex loop operations.  You can allow up to three additions/subtractions
   mutating loop registers and cast operations.  Any branches, calls, or unrecognized user opcodes will abort the scan.
5. Scan descendents of the three MULTIEQUAL/Phi opcodes, replacing any descendent varnodes with the input varnodes found in step 2.
   Move these three MULTIEQUAL/Phi opcodes to a deletion list.
6. Delete all matched opcodes in the reverse order they are found.