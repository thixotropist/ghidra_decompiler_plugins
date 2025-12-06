/**
 * @file riscv_vector_doc.hh

@page riscv_vector_transform_design RISC-V Vector Transform Design Study

@section rv_intro Introduction and Design

This plugin offers transformations of common RISC-V vector patterns into
C or C++ code offering more semantic clarity.  We start with GCC vectorization
of common glibc library patterns like `memcpy` and `strlen`, then try to
generalize to loop vectorization code likely found in AI, Machine Learning, and
embedded system Inference Engine applications.

@subsection riscv_vector_memcpy Vector memcpy
@verbatim
LAB_00020a3e
00020a3e  vsetvli  a3,param_2              ; e8m1tama
00020a42  vle8.v   v1,(param_1)
00020a46  c.sub    param_2,a3
00020a48  c.add    param_1,a3
00020a4a  vse8.v   v1,(this)
00020a4e  c.add    this,a3
00020a50  c.bnez   param_2,LAB_00020a3e
@endverbatim

The corresponding Ghidra Pcode for this loop is:

@verbatim
0x20a3e: a2(0x00020a3e:a8) = a2(0x00020a46:46) ? a5(0x000209ee:24) ? a5(0x000209ee:24)
0x20a3e: a1(0x00020a3e:a3) = a1(0x00020a48:47) ? a1(i) ? a1(i)
0x20a3e: a0(0x00020a3e:9e) = a0(0x00020a4e:4a) ? a0(0x000209c8:c) ? a0(0x00020a28:62)
0x20a3e: a3(0x00020a3e:43) = vsetvli_e8m1tama(a2(0x00020a3e:a8))
0x20a42: v1(0x00020a42:45) = vle8_v(a1(0x00020a3e:a3))
0x20a46: u0x1000001a(0x00020a46:cf) = a3(0x00020a3e:43) * #0xffffffffffffffff
0x20a46: a2(0x00020a46:46) = a2(0x00020a3e:a8) + u0x1000001a(0x00020a46:cf)(*#0x1)
0x20a48: a1(0x00020a48:47) = a1(0x00020a3e:a3) + a3(0x00020a3e:43)(*#0x1)
0x20a4a: vse8_v(v1(0x00020a42:45),a0(0x00020a3e:9e))
0x20a4e: a0(0x00020a4e:4a) = a0(0x00020a3e:9e) + a3(0x00020a3e:43)
0x20a50: u0x00018500:1(0x00020a50:4b) = a2(0x00020a46:46) != #0x0
0x20a50: goto r0x00020a3e:1(free) if (u0x00018500:1(0x00020a50:4b) != 0)
@endverbatim

This should transform into `vector_memcpy(this, param_1, param_2)`

Features:

 - 8 bit elements, multiplier=1
 - Three vector opcodes (vset, vle, vse)
 - Three arithmetic opcodes (&src, &dst, cnt)
 - simple loop with conditional branch
 - variable number of elements
 - common vector register (v1)
 - void result
 - four scratch registers (this, param_1, param_2, a3) with no external descendents

@subsection riscv_vector_strlen Vector strlen

@verbatim
000209ce  c.li     a3,0x0
000209d0  c.mv     a5,param_1
LAB_000209d2:
000209d2  vsetvli  param_2,zero            ; e8m1tama
000209d6  c.add    a5,a3
000209d8  vle8ff.v v1,(a5)
000209dc  vmseq.vi v1,v1,0x0
000209e0  csrrs    a3,vl,zero
000209e4  vfirst.m a6,v1
000209e8  blt      a6,zero,LAB_000209d2
000209ec  c.add    a5,a6
@endverbatim

The corresponding Ghidra Pcode for the loop component is:

@verbatim
0x209d2: a5(0x000209d2:bb) = a1(i) ? a5(0x000209d6:16)
0x209d2: a3(0x000209d2:b2) = a3(0x000209ce:13) ? vl(i)
0x209d2: a2(0x000209d2:15) = vsetvli_e8m1tama(#0x0)
0x209d6: a5(0x000209d6:16) = a5(0x000209d2:bb) + a3(0x000209d2:b2)(*#0x1)
0x209d8: v1(0x000209d8:18) = vle8ff_v(a5(0x000209d6:16))
0x209dc: v1(0x000209dc:1a) = vmseq_vi(v1(0x000209d8:18),#0x0)
0x209e4: a6(0x000209e4:20) = vfirst_m(v1(0x000209dc:1a))
0x209e8: u0x00001f80:1(0x000209e8:21) = a6(0x000209e4:20) < #0x0
0x209e8: goto r0x000209d2:1(free) if (u0x00001f80:1(0x000209e8:21) != 0)
@endverbatim


This should transform into `a5 = vector_strlen(param_1)`

Features:

 - 8 bit elements, multiplier=1
 - Four vector opcodes plus one vector status register opcode
 - One arithmetic opcode (&src) in loop
 - One arithmetic opcode after loop
 - Variable and unlimited number of elements
 - Fault_first load
 - no vector or scalar store
 - Simple loop with one non-contiguous predecessor opcode and one contiguous trailing opcode
 - common vector register (v1)
 - scalar int result (a5)
 - scratch registers (a3, a5, a6) with no external descendents

@subsection riscv_vector_reduction Floating Point Inner Product

The next sample is a stretch goal, something to analyze for common features that
can be easily generalized from simpler patterns.

The C source code is roughly:

@code{.cc}
static void ggml_vec_dot_f32(int n, const float * restrict x, const float * restrict y)
{
    double sumf = 0.0;
    for (int i = 0; i < n; ++i) {
        sumf += (double)(x[i]*y[i]);
    }
    *s = sumf;
}
@endcode

The Ghidra listing:

@verbatim
000d48c2      vsetvli      a4,zero                ;e64m1tama
000d48c6      vmv.v.i      v2,0x0
LAB_000d48ca:
000d48ca      vsetvli      a4,a0                  ;e32mf2tama
000d48ce      vle32.v      v3,(a3)
000d48d2      vle32.v      v1,(a5)
000d48d6      c.sub        a0,a4
000d48d8      sh2add       a3,a4,a3
000d48dc      sh2add       a5,a4,a5
000d48e0      vfmul.vv     v1,v1,v3
000d48e4      vmv1r.v      v3,v2
000d48e8      vfwadd.wv    v2,v3,v1
000d48ec      c.bnez       a0,LAB_000d48ca
000d48ee      vsetvli      a5,zero                ;e64m1tama
000d48f2      vmv.s.x      v1,zero
000d48f6      c.ldsp       ra,0x8(sp)
000d48f8      vfredusum.vs v2,v2,v1
000d48fc      c.ldsp       s0,0x0(sp=>local_10)
000d48fe      vfmv.f.s     fa5,v2
000d4902      fcvt.s.d     fa5,fa5,dyn
000d4906      fsw          fa5,0x0(a1)
000d490a      c.addi       sp,0x10
000d490c      ret
@endverbatim

This code forms the double precision inner product from
two single precision vectors, returning the result as
a single precision value.

@section riscv_vector_models Modeling vectorized loops

Vectorized loops can be split into categories based on
the number of vector loads and vector stores.
- `vector_memcpy` has one each vector load and vector store.
- `vector_strlen` has one vector load and no vector store.
- Reduction patterns also have one vector load and no vector store.
- Inner product patterns have two vector loads and no vector store.

Although not shown above, loops can be unrolled such that a single
vector is loaded in stripes, with two or four similar vector load operations
occurring within each loop iteration.  This leads us to a possible
factorization of vectorized loops, where we identify components of
vector iterators and transforms.

The `vector_memcpy` example above might be
narrowly transformed into `vector_memcpy(dest, src, size)` or
more generally transformed into:

@code{.cc}
std::transform(src.begin(), src.end(), dest.begin(),
                   [](char s) { return s; }); // the Lambda is a simple passthrough no-op
@endcode

The inner product example might become:

@code{.cc}
double custom_multiply = [](float x, float y) { return (double)x * (double)y; }; // Custom element-wise operation
double custom_add = [](double acc, double prod) { return acc + prod; }; // Custom accumulation operation
float result_custom = std::inner_product(x.begin(), x.end(), y.begin(), 0.0, custom_add, custom_multiply);
@endcode

How do these models drive our refactoring?

- We want to collect PcodeOp sequences into vector iterators, with initial values,
  incrementor, and vector load operations.
- Vector iterators are collected into source and destination iterators.
- Allow zero to two source iterators to cover inner-product cases
- Allow zero or one destination iterator
- Conditionals can be either counter-based, pointer-based or data-value based.
- per-element transformations are collected into lambda calculations.

We're missing something that captures the size of source and destination vectors.

@subsection riscv_vector_models_strlen Modeling Strlen Operations

How do we model vectorized encodings of `strlen`?  An unpatched Ghidra disassembles this as:

@code{as}
000209ce c.li     a3,0x0
000209d0 c.mv     a5,param_1
LAB_000209d2:
000209d2 vsetvli  param_2,zero               ; e8m1tama
000209d6 c.add    a5,a3
000209d8 vle8ff.v v1,(a5)
000209dc vmseq.vi v1,v1,0x0
000209e0 csrrs    a3,vl,zero
000209e4 vfirst.m a6,v1
000209e8 blt      a6,zero,LAB_000209d2
000209ec c.add    a5,a6
000209ee c.sub    a5,param_1
@endcode

The most natural way to render this would be:
@code{cc}
a5 = strlen(param_1);
@endcode

An alternate rendering based on the c++ standard library might be:

@code{cc}
auto it = std::find_if(param_1.begin(), param_1.end(), [](uint8_t b) {
         return b == 0; });
a5 = std::distance(param_1.begin(), it);
@endcode

Issues include:
- The alternate rendering conflates a standard vector with a char *.
- param_1 has no known end
- would a `vector_find_if` or `vector_e8_find_if` be a better choice to apply the lambda?

Can we remove some of the `std::vector` elements in favor of simple C array's?

@code{cc}
char* p = vector_find_if(param_1, [](uint8_t b) {return b == 0;});
a5 = p - param_1;
@endcode

Or try to reconstruct the loop itself, avoiding the lambda expression altogether:

@code{cc}
for (char* p = param_1; *p != 0; p++);
a5 = p - param_1;
@endcode

The minimalist solution would be to leave the vector loop unchanged, adding a comment block
to identify the loop as a likely strlen.

The recurring themes here may help us find the first steps along a path we can later extend:

- Vector loop stanzas may be terminated by some combination of a vector element data test (a lambda expresion), a
  counter, or a pointer limit expression.  This suggests a `VectorLoop::terminationFlags` bitmap.
- Translating vector expressions into their equivalent element-by-element scalar pcode is
  useful in several potential renderings.

@section riscv_vector_algorithms Transform Algorithms

All of these examples share a common component - a sequence of instructions forming
a simple loop (or a `Block`, in Ghidra terms) with a `vsetvli` instruction at the beginning
and a conditional branch at the end.  Some patterns will have a short prefix sequence to
set up loop registers and/or a suffix sequence to finalize a result.  We will
start by searching for that simple block pattern, then extend the search before and after as
necessary to accumulate prefix and suffix elements.

> Note: scalar and vector registers modified within the loop are assumed to be purely
>      local - and not available as possible parameters to subsequent function calls.

@subsection riscv_vector_scalability Scalability

The first iteration of the code showed how a single transform could be completed, a `vector_memcpy`.
Adding a second transform like `vector_strlen` wouldn't be too hard, but adding many transforms to
the current code base would be a scalability disaster.  The `VectorMatcher::examine_loop_pcodeops`
member function is a good example.  It includes a `switch` statement that provides code for each
Ghidra PcodeOp type.  For the CALL_OTHER PcodeType it then enters a forest of `if...then` clauses
to handle groups of different RISC-V user pcodes.  There are currently over 1300 user pcodeops defined,
with run-time identifiers assigned, so another `switch` statement is not feasible.

Instead, let's add a `map` of callback functions for vector opcodes found within loops,
loop prefixes, and loop suffixes.  For `vector_strlen` that means callback functions for
`vle8ff_v`, `vmseq_vi`, and `vfirst_m`.  For `vector_memcpy` that means callback functions for
`vle8_v`, and `vse8_v`.  We'll build those callback functions as lambda expressions, inserted
into the map during a static initialization phase.

@subsection riscv_vector_design_notes Design Working Notes

Summarize the current design first.  We start by requesting a call-back for every `vset*` instruction,
then analyze every loop that begins with a `vset*` instruction.  The loop analysis consists of these steps:

- `VectorLoop::examine_control_flow` to identify the bounds of the loop and verify it as a simple loop
  common to vector stanzas.
- `VectorLoop::collect_phi_nodes` to collect the Phi nodes at the top of the loop.  These show the registers
  modified during the loop and their external initializations.
- `VectorLoop::examine_loop_pcodeops` examines each of the Ghidra PcodeOps within the loop, collecting the native Ghidra
  scalar operations and the RISC-V vector CALL_OTHER operations in separate vectors.
- TODO: identify arguments of any vector load and store instructions, tracing pointer registers and their loop increments
- TODO: identify any counter register operations leading to a conditional branch
- TODO: identify register descendents of loop operations to be used in any transforms and dependency pruning.

Once generic vector analysis is complete specific tests can be applied.

- `VectorMatcher::isMemcpy` applies VectorLoop generic tests first, then match-specific tests to identify
  `vector_memcpy` stanzas.
- `VectorMatcher::isStrlen` similarly applies its own VectorLoop generic tests first, then match-specific tests to identify
  `vector_strlen` stanzas
*/