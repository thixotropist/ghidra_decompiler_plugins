---
title: Design Survey
description: Survey DPDK for priorities in networking and driver-centric analyses
weight: 140
---

What further Ghidra analyses and plugins would benefit most from processor-specific plugins?
Work to date has concentrated on transforming common RISC-V vector instruction sequences into
well-known library functions like `memcpy`.  Vector instructions are found in many other contexts,
making for confusing decompiler outputs.  Modern compilers can transform
general loops into vectorized sequences which have no direct and well-known library representation.

The goal here is to take a sample binary, `dpdk-l3fwd`, and explore decompiler code that adds clarity to a reverse engineering
exercise at reasonable cost.  Given a sample function from such a binary, the key questions are often:

* Do I care enough about what this function does to understand its internals?
* What additional tools might be helpful in deciding the function can be safely ignored?
* What is the complexity and generality of those additional tools?

There's a higher level question to be resolved too - what are the tradeoffs between decompiler correctness and decompiler generated
insight?  Do we need the decompiler to faithfully show how all corner cases are handled, or just provide a sufficiently good approximation
of the function's semantics to establish its relevance?

Start with a survey of dpdk-l3fwd to see what patterns are most common.

1. Export the entire dpdk-l3fwd executable to C
2. Extract the Vector summaries with
    ```console
    $ cat /tmp/riscv_summaries*|grep 'Vector instructions'  |sort > vector_results.txt
    ```
    2.9 million instructions, 23,000 functions, 7167 vector loops recognized
2. Count the similar patterns
    ```console
    $ uniq -c vector_results.txt|sort -rn|less
    ```

The most common patterns - after removing known `vector_memcpy` and similar patterns - are:

```text
272 	Vector instructions (handled | unhandled | epilog): | vsetvli_e64m1tama, vid_v, vrsub_vx, | ?
261 	Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf8tama, vle64_v, vse64_v, | ?
 48 	Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf8tama, vle64_v, vse64_v, | +, ?
 39 	Vector instructions (handled | unhandled | epilog): | vsetivli_e32mf2tama, vsetvli_e16mf4tama, vmv_v_i, minu, vse16_v, | ?
 34 	Vector instructions (handled | unhandled | epilog): | vsetvli_e32m1tama, vmv_v_x, vid_v, | ?
 32 	Vector instructions (handled | unhandled | epilog): | vsetivli_e32mf2tama, vmv_v_i, vsetvli_e16mf4tama, vmv_v_i, minu, | ?
 28 	Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf4tama, vle32_v, vse32_v, | ?
```

Let's examine a few of those.

## vsetvli_e64m1tama, vid_v, vrsub_vx

This is actually a prolog for a loop that copies 64 bit elements in reverse order.  The generated code implements the loop in several blocks:
* if the number of elements is small (less than 14) or able to fit entirely within the vector register (after checking `vlenb`), then a simple scalar
  loop is used with no vector components
* otherwise, a vector solution is used in several blocks
  * the `vid_v` and `vrsub_vx` instructions build an indexing vector like (3,2,1,0), if the full vector register can hold exactly four elements
  * a loop of `vl1re64_v`,  `vrgather_vv`, and `vsr1_v` instructions loads, reverses, and stores the elements so long as the vector register can be completely filled.
  * a scalar loop finishes any remaining elements that would not entirely fill a vector register.

A decent C++ display syntax for this kind of reverse copy pattern *might* be:

```cpp
// Using iterators
ranges::reverse_copy(first, last, d_first);

// Using a range (e.g., a standard container)
ranges::reverse_copy(source_range, d_first);
```

We can start with a binary generated from known source:

```cc
#include <algorithm>
#include <vector>
void reverse(std::vector<int>& a, std::vector<int>& b)
{
    std::ranges::reverse_copy(a, b.begin());
}
```

>Warning: methods like reverse_copy require the destination container already have enough space allocated to receive the copied elements.

Compile this with `-O3` and `-march=rv64gcv` and link it into a sharable object file, then give it to Ghidra.  Annotate the decompilation
to make the logic a bit clearer and get:

```c
/* reverse(std::vector<int, std::allocator<int> >&, std::vector<int, std::allocator<int> >&) */
void reverse(vector *param_1,vector *param_2)
{
  long nBytes;
  int *srcLast;
  ulong uVar1;
  int *dstBegin;
  int *srcEnd;
  int *srcBegin;
  long lVar2;
  ulong size;
  undefined1 auVar3 [32];
  undefined1 auVar4 [32];

  gp = &__global_pointer$;
  srcBegin = param_1->begin;
  srcEnd = param_1->end;
    /* Skip if source vector is empty */
  if (srcBegin != srcEnd) {
    srcLast = srcEnd + -1;
    /* vlenb = length of vector register, in bytes, or 16 for a 128 bit register
        size = number of 32 bit elements in the source vector */
    size = (ulong)((long)srcLast - (long)srcBegin) >> 2;
    dstBegin = param_2->begin;
    /* Use an entirely scalar loop if any of the following are true:
        * the source vector contents can't fill a vector register
        * the number of bytes to be copied is less than 25 (6 or fewer elements in the vector)
        * destination and source vectors overlap */
    if (((size < (vlenb >> 2) - 1) || ((ulong)((long)srcLast - (long)srcBegin) < 0x15)) ||
       ((nBytes = (long)srcEnd - (long)srcBegin,
        (ulong)(((nBytes << 0x3e) - nBytes) + (long)srcEnd) < (ulong)(nBytes + (long)dstBegin) &&
        (dstBegin < srcEnd)))) {
      while( true ) {
        *dstBegin = *srcLast;
        if (srcBegin == srcLast) break;
        srcLast = srcLast + -1;
        dstBegin = dstBegin + 1;
      }
      return;
    }
        /* Use vector instructions, prepping with a pointer offset vector like (3,2,1,0) */
    vsetvli_e32m1tama(0);
    auVar4 = vid_v();
    lVar2 = (vlenb >> 2) - 1;
    auVar4 = vrsub_vx(auVar4,lVar2);
    nBytes = (long)srcEnd - vlenb;
        /* reverse copy using the whole vector registers, regardless of vset instructions. */
    uVar1 = 0;
        /* note the redefinition of srcLast into a destination pointer */
    srcLast = dstBegin;
    do {
      auVar3 = vl1re32_v(nBytes);
      uVar1 = uVar1 + (vlenb >> 2);
      nBytes = nBytes - vlenb;
      auVar3 = vrgather_vv(auVar3,auVar4);
      vs1r_v(auVar3,srcLast);
      srcLast = (int *)((long)srcLast + vlenb);
    } while (uVar1 <= size - lVar2);
        /* Use a scalar loop to finish any vector elements beyond an integer number of
           full vector registers */
    if (size + 1 != uVar1) {
      srcEnd = srcEnd + -uVar1;
      dstBegin = dstBegin + uVar1;
      do {
        srcLast = srcEnd + -1;
        srcEnd = srcEnd + -1;
        *dstBegin = *srcLast;
        dstBegin = dstBegin + 1;
      } while (srcBegin != srcEnd);
    }
  }
  return;
}
```

We're not going to see a transformation of *that* anytime soon.  Perhaps we
might see the pattern partially recognized in the Survey code?

Alternatively, we might break this down into components:

```cpp
vsetvli_e32m1tama(0); auVar4 = vid_v(); lVar2 = (vlenb >> 2) - 1; auVar4 = vrsub_vx(auVar4,lVar2);
```

This might be replaced by `auVar4 = vector_reverse_index(vlenb >> 2)`.

```cpp
do {
    auVar3 = vl1re32_v(nBytes);
    uVar1 = uVar1 + (vlenb >> 2);
    nBytes = nBytes - vlenb;
    auVar3 = vrgather_vv(auVar3,auVar4);
    vs1r_v(auVar3,srcLast);
    srcLast = (int *)((long)srcLast + vlenb);
} while (uVar1 <= size - lVar2);
```

This might be replaced by a vector_full_register copy with transposition function.

## vsetvli_e8mf8tama, vle64_v, vse64_v

```c
uint *puVar9;
ulong uVar16;
uint *puVar14;
...
uVar16 = (ulong)(uVar1 - uVar2);
puVar9 = param_2;
do {
    lVar10 = vsetvli_e8mf8tama(uVar16);
    auVar20 = vle64_v(puVar9);
    uVar16 = uVar16 - lVar10;
    puVar9 = puVar9 + lVar10 * 2;
    vse64_v(auVar20,puVar14);
    puVar14 = puVar14 + lVar10 * 2;
} while (uVar16 != 0);
```

That one is a little confusing.  The relevant source code is:

```c
/* copy mbuf pointers to the application's packet list */
        for (i = 0; i < nb_pkts; ++i)
                rx_pkts[i] = stage[i];

```

The `e8mf8` term looks to be effectively the same as `e64m1`, since the `vle64` and `vse64` instructions will move 64 bit elements.
One difference is that the move is measured in bytes, not 64 bit elements.
That makes this essentially a variant of `vector_memcpy`, with the possibility of enforcing 64 bit memory alignment rules.

There are several similar vector sequences suggesting a pattern:

```text
vsetvli_e8mf8tama, vle64_v, vse64_v
vsetvli_e8mf4tama, vle32_v, vse32_v
vsetvli_e8mf2tama, vle16_v, vse16_v
vsetvli_e8m1tama, vle8_v, vse8_v
```

These may all be `std::ranges::copy(a, b.begin());` where the amount of data to copy is always specified in bytes, not elements, and any element
alignment rules are preserved.

## Design choices

We assume that the Ghidra user will prefer the decompiler to display

```c
vector_memcpy(dest, src, size);
```

rather than:

```as
memcpy_v1:
    vsetvli                        a3,size,e8,m1,ta,ma
    vle8.v                         v1,(src)
    c.sub                          size,a3
    c.add                          dest,a3
    vse8.v                         v1,(dest)
    c.add                          src,a3
    c.bnez                         size,memcpy_v1
```

That implicitly assumes:
* The user is not interested in the case that source and destination sizes overlap, or that the compiler has determined
  that this condition is not possible due to known memory layout data.
* The compiler treats registers `a3`, `src`, `dest`, and `size` as pure temporary registers with no descendants.
  Note that the plugin will avoid making this transform if the Ghidra decompiler can't verify that treatment.

The user might alternatively want to see this rendered as:

`std::ranges::copy(src, dest.begin());`

The dpdk survey raises more options, with common patterns like

```as
LAB_ram_0043ca70:
    vsetvli                        a5,t1,e8,mf8,ta,ma
    vle64.v                        v1,(t5)
    sub                            t1,t1,a5
    sh3add                         t5,a5,t5
    vse64.v                        v1,(a4)
    sh3add                         a4,a5,a4
    bne                            t1,zero,LAB_ram_0043ca70
```

This is very similar to a `vector_memcpy` sequence, with the added assumption that the elements are each 64 bits.
Presumably the compiler wants to avoid making byte-level memory accesses when 64 bit accesses are requested, either for
microarchitecture or performance reasons.

The design decision here is whether to map all of these to the typeless `vector_memcpy` representation or to try and infer
argument type information and pass that on to the decompiler.

Since this is a research project, let's add an experimental set of transforms with inferred typing, roughly based on the `std::ranges`
methods and/or `std::algorithms`.  The example above might be transformed into:

```cpp
void vector_ranges_copy(int64_t* srcBegin, int64_t* srcEnd, int64_t* dstBegin);
...
vector_ranges_copy(t5, t5+t1, a4);
```

The function `vector_ranges_copy` would be overloaded with multiple source type variants.

### lambda applications

If we want to pursue the C++ ranges or views representations, then the next step *could* be to find good early examples of
the `std::ranges::transform` methods.  In C++ this could look something like:

```cpp
std::vector<Item> items = {{1}, {2}, {3}};
std::vector<int> results(3);

// Eagerly transform into the 'results' vector
// Uses a projection to access '.value'
std::ranges::transform(items, results.begin(),
                        [](int v) { return v + 10; },
                        &Item::value);
```

Are there common patterns like this we can start to look at?  Nothing obvious stands out, so defer this path for now.
Instead, consider extending the survey code to generate hints for the user rather than transforms to manifest autonomously.
The dpdk function `eth_xtats_get_by_id` looks like the kind of complex vector stanza that badly needs some hints.
