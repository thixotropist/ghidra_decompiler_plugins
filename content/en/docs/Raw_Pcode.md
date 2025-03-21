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
0x00000004:3:	v1(0x00000004:3) = vle8_v(a1(i))  // output varnode is v1(0x00000004:3), pcodeop is CALLOTHER, input varnode 1 is vle8_v,
                                                // input varnode 2 is register a1 (likely an indirect varnode)
0x00000008:5:	vse8_v(v1(0x00000004:3),a0(i))    // no output varnode, pcodeop is CALLOTHER, input varnode 1 is vle8_v,
                                                // input varnode 2 is register a1, input varnode 3 is register a0
0x0000000c:6:	return(#0x0)
```

Note that Varnodes like `v1(0x00000004:3)` include both the register name (`v1`) and the pcode location at which the register was set (0x00000004:3).
The `i` field likely means this is an Indirect varnode, in this case provided externally via a function call.
