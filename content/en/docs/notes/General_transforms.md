---
title: General Transforms
description: Survey DPDK for paths to the generalized vector loop transforms
weight: 140
---

What vectorized loop patterns would benefit most from Ghidra transforms?  Work to date has
concentrated on well-known library functions like `memcpy`.  Modern compilers can transform
general loops into vectorized sequences which have no direct and well-known library representation.

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

** vsetvli_e64m1tama, vid_v, vrsub_vx

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

** vsetvli_e8mf8tama, vle64_v, vse64_v

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
That makes this essentially a variant of `vector_memcpy`, with the possibility of enforcing memory alignment rules.

There are several similar vector sequences suggesting a pattern:

```text
vsetvli_e8mf8tama, vle64_v, vse64_v
vsetvli_e8mf4tama, vle32_v, vse32_v
vsetvli_e8mf2tama, vle16_v, vse16_v
vsetvli_e8m1tama, vle8_v, vse8_v
```

These may all be `std::ranges::copy(a, b.begin());` where the amount of data to copy is always specified in bytes, not elements, and any element
alignment rules are preserved.