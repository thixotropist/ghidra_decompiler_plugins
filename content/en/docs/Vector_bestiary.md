---
title: Vector Bestiary
description: Some vector sequences are both common and too complex to easily transform into something recognizable.  We can collect some
             examples to help guide the user.
weight: 90
---

>Note: the organization of this page is very much TBD.  It might end up a separate folder with an index and lots of cross-links.

## eth_xtats_get_by_id

### Features

* accesses `vlenb` to determine the size of vector registers in order to reserve vector register-save space on the stack.
* demonstrates vector whole register loads and saves
* uses vector unordered indexed load
* vector loop is nested within another loop
* vector loop is followed by a method call of unknown signature

### Ghidra decompilation (annotated)
```c
long eth_xtats_get_by_id(rte_eth_dev *dev,uint64_t *ids,uint64_t *values,long size,uint basic_count)
{
  long lVar1;
  ulong k;
  undefined1 *puVar2;
  long lVar3;
  code *pcVar4;
  ulong uVar5;
  undefined8 uVar6;
  long n;
  long lVar7;
  undefined1 auVar8 [32];
  undefined1 auVar9 [32];
  undefined1 auVar10 [32];
  undefined1 auVar11 [32];
  undefined1 auVar12 [32];
  undefined1 ids_save [2056];

  gp = 0xfada38;
  if (size == 0) {
    return 0;
  }
  vsetvli_e64m1tama(0);
  auVar12 = vmv_v_x((ulong)basic_count);
  lVar1 = -vlenb;
  n = 0;
  lVar7 = 0;
  while( true ) {
    while( true ) {
      k = minu((long)((int)size - (int)n),0x100);
      if (size != n) break;
      vs1r_v(auVar12,(long)ids_save + lVar1);
      n = (**(code **)(dev->field88_0x58 + 0x2a8))(dev,ids_save,values + lVar7,k);
      auVar12 = vl1re64_v((long)ids_save + lVar1);
      if (n < 0) {
        gp = 0xfada38;
        return n;
      }
      lVar7 = (long)((int)n + (int)lVar7);
      n = (long)((int)k + (int)size);
    }
    vsetvli_e32mf2tama(0);
    auVar11 = vmv_v_x(n);
    auVar8 = vid_v();
    uVar5 = k & 0xffffffff;
    puVar2 = ids_save;
    do {
      lVar3 = vsetvli_e32mf2tama(uVar5);
      auVar9 = vadd_vv(auVar11,auVar8);
      vsetvli_e64m1tama(0);
      uVar5 = uVar5 - lVar3;
      auVar9 = vzext_vf2(auVar9);
      vsetvli_e32mf2tama(0);
      auVar10 = vmv_v_x(lVar3);
      vsetvli_e64m1tama(lVar3);
      auVar9 = vsll_vi(auVar9,3);
      uVar6 = vsetvli_e32mf2tama(0);
      auVar8 = vadd_vv(auVar8,auVar10);
      vsetvli_e64m1tama(lVar3);
      auVar9 = vluxei64_v(ids,auVar9);
      auVar9 = vsub_vv(auVar9,auVar12);
      vse64_v(auVar9,puVar2);
      puVar2 = puVar2 + lVar3 * 8;
    } while (uVar5 != 0);
    pcVar4 = *(code **)(dev->field88_0x58 + 0x2a8);
    vs1r_v(auVar12,(long)ids_save + lVar1);
    lVar3 = (*pcVar4)(dev,ids_save,values + lVar7,k,puVar2,pcVar4,0,uVar6);
    auVar12 = vl1re64_v((long)ids_save + lVar1);
    if (lVar3 < 0) break;
    n = (long)((int)k + (int)n);
    lVar7 = (long)((int)lVar3 + (int)lVar7);
    if (size == n) {
      return lVar7;
    }
  }
  gp = 0xfada38;
  return lVar3;
}
```

### likely source code

```c
static int
eth_xtats_get_by_id(struct rte_eth_dev *dev, const uint64_t *ids,
        uint64_t *values, uint32_t size, uint32_t basic_count)
{
    int32_t rc;
    uint32_t i, k, m, n;
    uint64_t ids_copy[ETH_XSTATS_ITER_NUM];
    m = 0;
    for (n = 0; n != size; n += k) {
        k = RTE_MIN(size - n, RTE_DIM(ids_copy));
        /*
         * Convert ids to xstats ids that PMD knows.
         * ids known by user are basic + extended stats.
         */
        for (i = 0; i < k; i++)
                ids_copy[i] = ids[n + i] - basic_count;
        rc = dev->dev_ops->xstats_get_by_id(dev, ids_copy, values + m, k);
        if (rc < 0)
                return rc;
        m += rc;
    }
    return m;
}
```

### survey report

The current vector loop survey report doesn't help much, other than to point out that *none* of the vector instructions in the
inner loop currently have handlers defined.

```text
Vector Loop (simple):
        control structure is simple
        Loop start address: 0x338d72
        Loop length: 0x40
        setvli mode: element size=0, multiplier=0
        vector loads: 0
        vector stores: 0
        integer arithmetic ops: 4
        scalar comparisons: 1
        vector logical ops: 0
        vector integer ops: 0
        vector comparisons: 0
        vector source operands: 0
        vector destination operands: 0
        edges in: 1
        Vector instructions (handled | unhandled | epilog): | vsetvli_e32mf2tama, vadd_vv, vsetvli_e64m1tama, vzext_vf2, vsetvli_e32mf2tama, vmv_v_x, vsetvli_e64m1tama, vsll_vi, vsetvli_e32mf2tama, vadd_vv, vsetvli_e64m1tama, vluxei64_v, vsub_vv, vse64_v, | ?,
        Loop control variable: a6(0x00338d7e:4a) = a6(0x00338d72:108) + u0x1000001e(0x00338d7e:132)
        Loop Local-scope Varnodes: u0x1000001e(0x00338d7e:132), a6(0x00338d7e:4a), u0x0000ca00(0x00338dae:5b), a4(0x00338dae:5c), a6(0x00338d7e:4a),
```

### analysis

Vector registers need to be saved - or regenerated - across function calls.  In the decompiler window this pattern appears as

```c
lVar1 = -vlenb;
vs1r_v(auVar12,(long)ids_save + lVar1);
n = (**(code **)(dev->field88_0x58 + 0x2a8))(dev,ids_save,values + lVar7,k);
auVar12 = vl1re64_v((long)ids_save + lVar1);
```

* `ids_save` is the last variable saved at the bottom of the stack, so `ids_save - vlenb` refers to a new register save space allocated on the stack across the function call.
* the `vs1r_v` and `vl1re64_v` are whole register store and load instructions.
* the store and load statements could be supressed entirely,
  so long as the same vector register variable `auVar12` is
  used in both statements.

This sequence looks to be a poor optimization.  The constant vector `auVar12` is moved out of the loop, but the memory accesses
needed to save and restore it are likely slower than the CPU cycles needed to regenerate it as needed.

Now start collecting notes on the inner loop structure and register assignments.

* The inner loop has one vector load and one vector store separated by a vector subtraction.
* The vector elements are 64 bit integers
* The subtraction might be styled as a lambda expression `[basic_count](long x){return x - basic_count;}`
* The inner loop might be styled with C++ iterators as
  `std::transform(ids.begin() + n, ids.begin() + n + k, ids_copy.begin(), [basic_count](long x){return x - basic_count;})`
* The vector registers are then initialized in the outer loop:
    * `auVar12 = (basic_count, basic_count, ...)`
    * `auVar11 = (n, n, ...)`
    * `auVar8 = (0, 1, ...)`
* The inner loop vector registers mostly implement the iterators
    * `lVar3` is the number of 32 bit integers that fit into half of a vector register, so 4 if `vlenb==32`.
    * `auVar9 = sign_extend(auVar11 + auVar8)` or `(n, n + 1, ...) cast to 64 bit integers`
    * `auVar10 = vmv_v_x(lVar3)` or `(4, 4, ...)`
    * `auVar9 = auVar9 * 8` to convert from a vector of indices to a vector of pointer offsets into 64 bit vector elements
    * `auVar8` = `auVar8 + auVar10` or `(4, 5, ...)`
    * `auVar9 = *(auVar9 + ids)` or `(ids[n], ids[n+1], ...)`
    * `auVar9 = auVar9 - (basic_count, basic_count, ...)`
    * `*(puVar2) = auVar9`
* The inner loop terminates when `k` elements have been transformed.

## Reverse copy

A simple C++ statement can compile into a confusing nest of blocks.  This example occurs often enough in compiled code, but
we'll use a slightly artificial example to make the point.

### Features

* accesses `vlenb` to determine the size of vector registers to choose vector over scalar computations
* demonstrates vector whole register loads and saves to process vector elements
* implements the operation with both scalar and vector loops, depending on arguments
* uses a vector gather instruction to permute/reverse vector elements

```cpp
#include <algorithm>
#include <vector>
void reverse(std::vector<int>& a, std::vector<int>& b)
{
    std::ranges::reverse_copy(a, b.begin());
}
```

### Ghidra decompilation (annotated)

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
     * size = number of 32 bit elements in the source vector
     */
    size = (ulong)((long)srcLast - (long)srcBegin) >> 2;
    dstBegin = param_2->begin;
    /* Use an entirely scalar loop if any of the following are true:
     * the source vector contents can't fill a vector register
     * the number of bytes to be copied is less than 25 (6 or fewer elements in the vector)
     * destination and source vectors overlap
     */
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
     * full vector register
     */
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
