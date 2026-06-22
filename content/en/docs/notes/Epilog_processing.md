---
title: Epilog transform processing
description: The epilog section of a vector loop transform presents challenges.  Collect examples and possible solutions here.
weight: 160
---

## Overview

Vector transforms like `vector_strlen` consist of a preamble (or setup) section, the loop, and an epilog section.  The epilog section finishes the transform and
merges the result Varnode into the follow-on processing.  That epilog section can show significant variability as the compiler sequences and optimizes the way that
result is actually used.  If the vector transform code fails to recognize the epilog code, it is very likely to remove PcodeOps and result Varnodes needed in the rest
of the function.  This usually results in a 'free Varnode` low-level error.

The possible solutions include:

1. Enhance each transform's epilog processing to recognize more patterns.  For instance, the `vector_strlen` epilog can either return an integer or the address of the last
   character in the given string.  The current code fails to distinguish these patterns.
2. Perform epilog pattern recognition earlier in the processing, aborting a transform if the transform may produce a low-level error.
3. Perform epilog processing in a transactional context, so that problems encountered late in the transform can force a roll-back of all changes.

### Examples

The simplest `vector_strlen` epilog pattern can be just 4 bytes long:

```as
strlen:
    c.li        a3,0x0
    c.mv        a5,a0
0:
    vsetvli     a2,zero,e8,m1,ta,ma
    c.add       a5,a3
    vle8ff.v    v1,(a5)
    vmseq.vi    v1,v1,0x0
    csrr        a3,vl
    vfirst.m    a6,v1
    blt         a6,zero,0b
    c.add       a5,a6      ; epilog begins
    c.sub       a5,a0      ; epilog ends
    c.mv        a0,a5
    ret
```

Other instructions can appear within the epilog sequence, without being part of the epilog.  These must be preserved while the addition and subtraction instructions should be deleted along with all
instructions within the loop.

The existing code recognizes the instructions following the loop end as possible epilog instructions:

```text
Possible Epilog Pcode: u0x10000000(0x00100020:18) = a0(i) * #0xffffffffffffffff
Possible Epilog Pcode: u0x10000008(0x00100020:1a) = u0x10000000(0x00100020:18) + a6(0x00100016:a)
Possible Epilog Pcode: a5(0x00100020:e) = a5(0x00100008:4) + u0x10000008(0x00100020:1a)(*#0x1)
Possible Epilog Pcode: a0(0x00100022:f) = a5(0x00100020:e)
Possible Epilog Pcode: return(#0x0) a0(0x00100022:f)
```

It then looks for the intersection of two descendant sets: the vector load address register `a5` and the `vfirst` result `a6`.  The intersection is `a5(0x00100020:e)`, which is then
identified as the `vector_strlen` result Varnode.

A slightly different function has the same prolog and loop structure, but with a variant epilog:

```as
strend:
    c.li        a3,0x0
    c.mv        a5,a0
0:
    vsetvli     a2,zero,e8,m1,ta,ma
    c.add       a5,a3
    vle8ff.v    v1,(a5)
    vmseq.vi    v1,v1,0x0
    csrr        a3,vl
    vfirst.m    a6,v1
    blt         a6,zero,0b
    c.add       a5,a6     ; epilog begins
    c.li        a1,1
    c.sub       a5,a1     ; epilog ends
    c.mv        a0,a5
    ret
```

This function returns a pointer to the last non-null byte in the string.  The existing code mistakenly transforms this into:

```c
long strend(long param_1)
{
  undefined8 uVar1;
  uVar1 = vector_strlen((char *)param_1);
  return uVar1 + -1;    // should return param_1 + uVar1 -1;
}
```

### Code overview

The existing code commits to *attempting* a `vector_strlen` transformation based on what it finds within the loop.  It commits to *executing*
a `vector_strlen` transformation once it has identified a result Varnode and the loop-external Varnode providing the string address.  The code
can abort the transform for several reasons, such as failure to find the string address Varnode or dependencies found for loop-local Varnodes.
