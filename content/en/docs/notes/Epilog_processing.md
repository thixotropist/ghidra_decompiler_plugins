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

>Note: The examples here show earlier results *before* a better heuristic was identified and installed.

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
Possible Epilog Pcode: a5(0x0010001e:d) = a5(0x00100008:4) + a6(0x00100016:a)
Possible Epilog Pcode: u0x10000000(0x00100020:18) = a0(i) * #0xffffffffffffffff
Possible Epilog Pcode: a5(0x00100020:e) = a5(0x0010001e:d) + u0x10000000(0x00100020:18)
Possible Epilog Pcode: a0(0x00100022:f) = a5(0x00100020:e)
Possible Epilog Pcode: return(#0x0) a0(0x00100022:f)
```

It then traces the descendants of the vector load source register (as root1) and those of the comparison register a6 (as root2):

```text
intersection set root1: a5(0x00100020:e), a5(0x00100008:4), a6(0x00100016:a), a5(0x0010001e:d), v1(0x0010000e:8), u0x00004200:1(0x0010001a:b), a0(0x00100022:f), a5(0x00100004:15), v1(0x0010000a:6),
intersection set root2: a5(0x00100020:e), a5(0x0010001e:d), u0x00004200:1(0x0010001a:b), a0(0x00100022:f),
```

The epilog processing code then determines the intersection of these two sets, after excluding any in-loop Varnodes.  The first such intersection Varnode in the register space is taken as the result Varnode:

```text
Checking for in-loop definition: u0x00004200:1(0x0010001a:b)
        addressInLoop = true
        blockIsLoopblock = true
Checking for in-loop definition: a5(0x0010001e:d)
        addressInLoop = false
        blockIsLoopblock = false
Checking for in-loop definition: a5(0x00100020:e)
        addressInLoop = false
        blockIsLoopblock = false
Checking for in-loop definition: a0(0x00100022:f)
        addressInLoop = false
        blockIsLoopblock = false
        Potential result Varnodes after sorting and filtering: : a5(0x0010001e:d), a5(0x00100020:e), a0(0x00100022:f),
Selecting as the result Varnode a5(0x0010001e:d)
```

Which is wrong - the correct result Varnode is `a5(0x00100020:e)`.

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

```text
Possible Epilog Pcode: a5(0x001000d8:d) = a5(0x001000c2:4) + a6(0x001000d0:a)
Possible Epilog Pcode: a5(0x001000dc:10) = a5(0x001000d8:d) + #0xffffffffffffffff
Possible Epilog Pcode: a0(0x001000de:11) = a5(0x001000dc:10)
Possible Epilog Pcode: return(#0x0) a0(0x001000de:11)
       intersection set root1: a5(0x001000be:17), a5(0x001000d8:d), a5(0x001000c2:4), u0x00004200:1(0x001000d4:b), v1(0x001000c4:6), a0(0x001000de:11), a5(0x001000dc:10), v1(0x001000c8:8), a6(0x001000d0:a),
       intersection set root2: a5(0x001000d8:d), u0x00004200:1(0x001000d4:b), a0(0x001000de:11), a5(0x001000dc:10),
       Checking for in-loop definition: u0x00004200:1(0x001000d4:b)
               addressInLoop = true
               blockIsLoopblock = true
       Checking for in-loop definition: a5(0x001000d8:d)
               addressInLoop = false
               blockIsLoopblock = false
       Checking for in-loop definition: a5(0x001000dc:10)
               addressInLoop = false
               blockIsLoopblock = false
       Checking for in-loop definition: a0(0x001000de:11)
               addressInLoop = false
               blockIsLoopblock = false
               Potential result Varnodes after sorting and filtering: : a5(0x001000d8:d), a5(0x001000dc:10), a0(0x001000de:11),
       Selecting as the result Varnode a5(0x001000d8:d)
```

This result is also incorrect.  The epilog should transform - if the transformation is attempted at all - into something like

```text
u0x001000d8:8 = vector_strlen(a5(0x001000c2:4))
a5(0x001000d8:xx) = u0x001000d8:8 + a5(0x001000c2:4)
a5(0x001000dc:10) = a5(0x001000d8:xx) + #0xffffffffffffffff
a0(0x001000de:11) = a5(0x001000dc:10)
```

### Code overview

The existing code commits to *attempting* a `vector_strlen` transformation based on what it finds within the loop.  It commits to *executing*
a `vector_strlen` transformation once it has identified a result Varnode and the loop-external Varnode providing the string address.  The code
can abort the transform for several reasons, such as failure to find the string address Varnode or dependencies found for loop-local Varnodes.

## Path forward

We need surveys of strlen and strcmp epilog sequences, hopefully leading up to a better set of filters for the result candidates.

With basic survey code in place, we need a more structured epilog handling approach.

The first `vector_strlen` example produced this epilog:

```text
a5(0x0010001e:d) = a5(0x00100008:4) + a6(0x00100016:a)
u0x10000000(0x00100020:18) = a0(i) * #0xffffffffffffffff
a5(0x00100020:e) = a5(0x0010001e:d) + u0x10000000(0x00100020:18)
```

The first element in the intersection set was `a5(0x0010001e:d)`.  The true result was `a5(0x00100020:e)`.
Valid epilog patterns include:

* `a5 = a5 + a6; u0 = a0 * -1; a5 = a5 + u0;`
* `u0 = a0 * -1; a5 = a5 + a6; a5 = a5 + u0;`
* `u0 = -a0 ; a5 = a5 + a6; a5 = a5 + u0;`
* `u0 = a0 ; a5 = a5 + a6; a5 = a5 - u0;`
* etc.

That's unmanageable, with too many variations and orderings.

Let's examine the potential intersection candidates again:

```text
a5(0x0010001e:d), a5(0x00100020:e), a0(0x00100022:f)
```

We need to see both an addition and a subtraction, so perhaps the simplest selector is to take the second addition/subtraction
operation from the result list if it holds more than one potential result.

Rough heuristics are in place, so run the integration test to check for divergence:

```text
Error: Unexpected number (0) of vector_strlen transforms found in whisper_sample_5	Expected: 1 transforms
Error: Unexpected number (0) of vector_strlen transforms found in whisper_sample_17	Expected: 1 transforms
Error: Unexpected number (2) of vector_strlen transforms found in whisper_sample_18	Expected: 4 transforms
Error: Unexpected number (1) of vector_strlen transforms found in whisper_sample_19	Expected: 4 transforms
```

Examine these four divergences individually, to see if we can modify heuristics or alter the correct number of transforms.

### whisper_sample_5

Log extracts:

```text
Analyzing potential vector loop stanza at 0xb9946 in pid:tid 873464:873464
Beginning loop pcode analysis
  PcodeOp at 0xb9946: a5(0x000b9946:1102) = a0(0x000b993c:109) ? a5(0x000b994a:10f)
  PcodeOp at 0xb9946: a3(0x000b9946:1019) = a3(0x000b9944:10d) ? c0x0c20(i)
  PcodeOp at 0xb9946: vsetvli_e8m1tama(#0x0)
  PcodeOp at 0xb994a: a5(0x000b994a:10f) = a5(0x000b9946:1102) + a3(0x000b9946:1019)(*#0x1)
  PcodeOp at 0xb994c: v1(0x000b994c:111) = vle8ff_v(a5(0x000b994a:10f))
  PcodeOp at 0xb9950: v1(0x000b9950:113) = vmseq_vi(v1(0x000b994c:111),#0x0)
  PcodeOp at 0xb9958: a1(0x000b9958:115) = vfirst_m(v1(0x000b9950:113))
  PcodeOp at 0xb995c: u0x00004200:1(0x000b995c:116) = a1(0x000b9958:115) < #0x0
  PcodeOp at 0xb995c: goto Block_9:0x000b9946 if (u0x00004200:1(0x000b995c:116) != 0) else Block_10:0x000b9960
...
Possible Epilog Pcode:
 u0x1000017d(0x000b9966:1334) = a0(0x000b993c:109) * #0xffffffffffffffff
 u0x10000415(0x000b9966:23e6) = u0x1000017d(0x000b9966:1334) + a1(0x000b9958:115)
 a5(0x000b9966:11c) = a5(0x000b994a:10f) + u0x10000415(0x000b9966:23e6)(*#0x1)
 a5:4(0x000b996a:10a3) = SUB84(a5(0x000b9966:11c),#0x0:4)
 s6:4(0x000b996a:11dd) = SUB84(s6(0x000b991e:11f0),#0x0:4)
 u0x0001fc00:4(0x000b996a:11d) = a5:4(0x000b996a:10a3) + s6:4(0x000b996a:11dd)
...
Potential result Varnodes after sorting and filtering: : a5(0x000b9966:11c), a5:4(0x000b996a:10a3)
Unable to find resultVn, abandon strlen transform
```

The problem here is we are only considering PcodeOps in the register space, not in the temporary space.
Fix that with a more comprehensive filter and see that the integration tests pass - except for those waiting for upstream
fixes.

## Handle variant epilogs

Add some code to handle the vector_strlen epilog specific to the `strend` function example above.  This
code recognizes the compiler optimizations and now decompiles to:

```c
long strend(long param_1)
{
  undefined8 uVar1;
  uVar1 = vector_strlen((char *)param_1);
  return (uVar1 + param_1) - 0xffffffffffffffff;
}
```