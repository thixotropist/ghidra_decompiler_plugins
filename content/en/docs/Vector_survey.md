---
title: Vector Survey
description: What common vector instruction sequences are worth transforming?  What is a good sequence for developing the Actions implementing those transforms?
weight: 20
---

The starting point is very simple:

* the semantics can be replaced with a single `builtin_memcpy`,
* the number of elements to copy is known to the compiler and fits entirely within the vector registers,
* the vector instructions are all within a single Ghidra Block
* no loops or conditional instructions are needed

The next steps might vary these conditions with:

* the semantics can be replaced with two or more `builtin_memcpy` invocations
* the semantics can be replaced with a single `builtin_memset(0)`,
* the number of elements to copy is not known to the compiler, requiring an internal loop.

Let's look at a build of Whisper-cpp for a RISC-V 64 bit processor, using GCC 15.0 as the compiler.
* What vector sequences are most often found in the binary?
* Are these sequences in general purpose code (`main`, input and output, ...) or special purpose
  vector code (vector dot product, ...)
* Categorize these sequences based on frequency and expected transform difficulty
* Generate data tests to capture common patterns and drive additional rules and transforms.

We can also include survey examples from the Data Path Development Kit distribution.  It has no
vector math components but many loops over arrays of structures that get compiled into
surprisingly complex vector sequences.

Ghidra finds 275K instructions in this `whisper-cpp` executable, with roughly 8% being vector instructions.  

## Loop-free patterns

### initialization sequences

This block includes seven `vsetivli` instructions, three vector memory loads, a vector immediate load, and four vector stores.
The block occurs during the initialization of `main`, so it is likely important to transform into something easily understood.

```as
LAB_0002104e: 
jal      ra,whisper_full_default_params
lw       a5,-0x5f8=>local_5f8(s0)
c.mv     a1,s1
c.mv     a0,s2
sw       a5,-0x280=>whisper_params.field32_0x20(s0)
jal      ra,whisper_full_default_params
auipc    a3,0xe7
addi     a3=>DAT_00107f20,a3,-0x142
vsetivli zero,0x4,e32,m1,ta,ma 
vle32.v  v3,(a3)
auipc    a4,0xe7
addi     a4,a4,-0x65a
vsetivli zero,0x2,e32,mf2,ta,ma
vle32.v  v2,(a4)
auipc    a5,0xe7
addi     a5,a5,-0x662
vsetivli zero,0x8,e8,mf2,ta,ma 
vle8.v   v1,(a5)
lw       a5,-0x5f4=>local_5f4(s0)
vsetivli zero,0x10,e8,m1,ta,ma  
vmv.v.i  v4,0x0
sw       a5,-0x27c=>whisper_params.field36_0x24(s0)
addi     a5,s0,-0x800
addi     a0,s0,-0x240
addi     a5,a5,-0xc8
c.sd     a0,0x0(a5=>local_8c8)
addi     a5,s0,-0x258
vse8.v   v4,(a5)
auipc    a4,0xd9
flw      fa5,0x84(a4=>DAT_000fa13c)
addi     a5,s0,-0x274
vsetivli zero,0x4,e32,m1,ta,ma 
vse32.v  v3,(a5)
addi     a5,s0,-0x264
vsetivli zero,0x2,e32,mf2,ta,ma
vse32.v  v2,(a5)
auipc    a1,0xdd
addi     a1=>DAT_000fdbd8,a1,-0x500
addi     a5,s0,-0x248
vsetivli zero,0x8,e8,mf2,ta,ma 
vse8.v   v1,(a5)
sw       zero,-0x278=>whisper_params.field40_0x28(s0)
fsw      fa5,-0x25c=>whisper_params.field68_0x44(s0)
jal      ra,std::string::string<>
addi     s1,s0,-0x210
addi     a0,s0,-0x200
auipc    a1,0xdd
addi     a1=>s_/System/Library/Fonts/Supplement_000fdbe   = "/System/Library/Fonts/Supplem
sd       zero,-0x218=>whisper_params.field136_0x88(s0)
sb       zero,-0x210=>whisper_params.field144_0x90(s0)
sd       s1,-0x220=>whisper_params.field128_0x80(s0)
```

The vector loads and stores are interleaved, likely to allow for memory latency.
This sometimes means `vset` instructions are issued twice, before each load or store.

Any Rule set operating on this might break it down as:

```as
vsetivli zero,0x4,e32,m1,ta,ma 
vle32.v  v3,(a3)
...                             // instructions which do not alter v3 but may alter vset parameters
vsetivli zero,0x4,e32,m1,ta,ma  // refresh vset parameters
vse32.v  v3,(a5)
```

These instructions should be transformed to `vector_memcpy(a5, a3, 16)`.

```as
vsetivli zero,0x2,e32,mf2,ta,ma
vle32.v  v2,(a4)
...
vsetivli zero,0x2,e32,mf2,ta,ma
vse32.v  v2,(a5)
```

These instructions should be transformed to `vector_memcpy(a5, a4, 8)`.

```as
vsetivli zero,0x8,e8,mf2,ta,ma 
vle8.v   v1,(a5)
...
vsetivli zero,0x8,e8,mf2,ta,ma 
vse8.v   v1,(a5)
```

These instructions *might* be transformed to `vector_memcpy(a5, a5, 8)`, but the a5 register has changed with the intermediate instructions.

```as
vsetivli zero,0x10,e8,m1,ta,ma  
vmv.v.i  v4,0x0
...
vse8.v   v4,(a5)                 // no vset refresh needed
```

These instructions should be transformed to `vector_memset(a5,0,16)`

## Loop patterns

### builtin_memcpy

### builtin_strlen

### reduction

### arrays of structures

### vector math

This is the kind of routine that dominates CPU time in ML or inference engine apps, and would be one of the last to
process via a new Ghidra Rule.

```as
 **************************************************************
 *                          FUNCTION                          *
 **************************************************************
 undefined ggml_vec_dot_f32()

 ggml_vec_dot_f32
    c.addi       sp,-0x10
    c.sdsp       s0,0x0(sp=>local_10)
    c.sdsp       ra,0x8(sp)
    c.addi4spn   s0,sp,0x10
    bge          zero,a0,LAB_000d490e
    vsetvli      a4,zero,e64,m1,ta,ma 
    vmv.v.i      v2,0x0
LAB_000d48ca          XREF[1]:     000d48ec(j)  
    vsetvli      a4,a0,e32,mf2,tu,ma
    vle32.v      v3,(a3)
    vle32.v      v1,(a5)
    c.sub        a0,a4
    sh2add       a3,a4,a3
    sh2add       a5,a4,a5
    vfmul.vv     v1,v1,v3
    vmv1r.v      v3,v2
    vfwadd.wv    v2,v3,v1
    c.bnez       a0,LAB_000d48ca
    vsetvli      a5,zero,e64,m1,ta,ma 
    vmv.s.x      v1,zero
    c.ldsp       ra,0x8(sp)
    vfredusum.vs v2,v2,v1
    c.ldsp       s0,0x0(sp=>local_10)
    vfmv.f.s     fa5,v2
    fcvt.s.d     fa5,fa5,dyn
    fsw          fa5,0x0(a1)
    c.addi       sp,0x10
    ret
LAB_000d490e          XREF[1]:     000d48be(j)  
    fmv.w.x      fa5,zero
    c.ldsp       ra,0x8(sp)
    c.ldsp       s0,0x0(sp=>local_10)
    fsw          fa5,0x0(a1)
    c.addi       sp,0x10
    ret
```

Features:

* multiple vsetvli instructions
  * one of which codes for 'tail unchanged' instead of the more common 'tail agnostic'
* floating point reduction and widening ops
* vector instructions span multiple blocks

Compiled from:

```c
static void ggml_vec_dot_f32(int n, float * restrict s, const float * restrict x, const float * restrict y)
{
    double sumf = 0.0;
    for (int i = 0; i < n; ++i) {
        sumf += (double)(x[i]*y[i]);
    }
    *s = sumf;
}
```

Potential transform result:

```c++
std::inner_product(x.begin(), x.end(), y.begin(), 0.0);
```

Notes:

* Type management in the midst of widening and reduction operations makes this messy.
* Most ML apps using routines like this would be more likely to operate on 5 bit floats,
  not 32 bit floats, making type management in Ghidra even more complicated.