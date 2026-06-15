---
title: Vector Bestiary
description: Some vector sequences are both common and too complex to easily transform into something recognizable.  We can collect some
             examples to help guide the user.
weight: 90
---

>Note: the organization of this page is very much TBD.  It might end up a separate folder with an index and lots of cross-links.

>DPDK Source is commit 0c0f70f98dcf5b860b2e422ad20f40cc9f1d3705 from https://github.com/DPDK/dpdk.git.  Unless noted, the compiler flags are `-march=rv64gcv -O3`.
>This asks for aggressive optimizations such as loop unrolling that are less likely to be found in current production code, which might use flags like `-march=rv64gcv -O2`

## eth_xtats_get_by_id

### Features

* accesses `vlenb` to determine the size of vector registers in order to reserve vector register-save space on the stack.
* demonstrates vector whole register loads and saves
* uses vector unordered indexed load
* vector loop is nested within another loop
* vector loop is followed by a method call of unknown signature

### Ghidra decompilation (annotated)
```c
ulong eth_xtats_get_by_id(rte_eth_dev *dev,uint64_t *ids,uint64_t *values,long size,
                         ulong basic_count)
{
  int iVar1;
  long lVar2;
  ulong uVar3;
  long lVar4;
  code *pcVar5;
  undefined1 *puVar6;
  undefined8 uVar7;
  long lVar8;
  ulong uVar9;
  undefined1 auVar10 [32];
  undefined1 auVar11 [32];
  undefined1 auVar12 [32];
  undefined1 auVar13 [32];
  undefined1 auVar14 [32];
  undefined1 auStack_860 [2056];
  gp = 0x1001cc0;
  if (size == 0) {
    return 0;
  }
  vsetvli_e64m1tama(0);
  auVar14 = vmv_v_x(basic_count & 0xffffffff);
  lVar2 = -vlenb;
  lVar8 = 0;
  uVar9 = 0;
  while( true ) {
    while( true ) {
      uVar3 = (ulong)((int)size - (int)lVar8);
      if (0x100 < uVar3) {
        uVar3 = 0x100;
      }
      iVar1 = (int)uVar3;
      if (size != lVar8) break;
      pcVar5 = *(code **)(dev->field88_0x58 + 0x2b0);
      vs1r_v(auVar14,(long)auStack_860 + lVar2);
      uVar3 = (*pcVar5)(dev,auStack_860,values + (uVar9 & 0xffffffff),(long)iVar1,uVar9 << 0x20,
                        pcVar5);
      auVar14 = vl1re64_v((long)auStack_860 + lVar2);
      if ((long)uVar3 < 0) {
        gp = 0x1001cc0;
        return uVar3;
      }
      uVar9 = (ulong)((int)uVar3 + (int)uVar9);
      lVar8 = (long)(iVar1 + (int)size);
    }
    vsetvli_e32mf2tama(0);
    auVar13 = vmv_v_x(lVar8);
    auVar10 = vid_v();
    uVar3 = uVar3 & 0xffffffff;
    puVar6 = auStack_860;
    do {
      lVar4 = vsetvli_e32mf2tama(uVar3);
      auVar11 = vadd_vv(auVar13,auVar10);
      vsetvli_e64m1tama(0);
      auVar11 = vzext_vf2(auVar11);
      vsetvli_e32mf2tama(0);
      auVar12 = vmv_v_x(lVar4);
      vsetvli_e64m1tama(lVar4);
      auVar11 = vsll_vi(auVar11,3);
      uVar3 = uVar3 - lVar4;
      auVar11 = vluxei64_v(ids,auVar11);
      uVar7 = vsetvli_e32mf2tama(0);
      auVar10 = vadd_vv(auVar10,auVar12);
      vsetvli_e64m1tama(lVar4);
      auVar11 = vsub_vv(auVar11,auVar14);
      vse64_v(auVar11,puVar6);
      puVar6 = puVar6 + lVar4 * 8;
    } while (uVar3 != 0);
    pcVar5 = *(code **)(dev->field88_0x58 + 0x2b0);
    vs1r_v(auVar14,(long)auStack_860 + lVar2);
    uVar3 = (*pcVar5)(dev,auStack_860,values + (uVar9 & 0xffffffff),(long)iVar1,uVar9 << 0x20,pcVar5
                      ,puVar6,uVar7);
    auVar14 = vl1re64_v((long)auStack_860 + lVar2);
    if ((long)uVar3 < 0) break;
    lVar8 = (long)(iVar1 + (int)lVar8);
    uVar9 = (ulong)((int)uVar3 + (int)uVar9);
    if (size == lVar8) {
      return uVar9;
    }
  }
  gp = 0x1001cc0;
  return uVar3;
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

The current vector loop survey report doesn't help much, other than to point out that *only one* of the vector instructions in the
inner loop currently have handlers defined.

```text
Vector Loop (simple):
        control structure is simple
        Loop start address: 0x352596
        Loop length: 0x40
        setvli mode: element size=0, multiplier=0
        vector loads: 0
        vector stores: 1
        integer arithmetic ops: 4
        scalar comparisons: 1
        vector logical ops: 0
        vector integer ops: 0
        vector comparisons: 0
        vector source operands: 0
        vector destination operands: 1
        edges in: 1
        Vector instructions (handled | unhandled | epilog): vse64_v, | vsetvli_e32mf2tama, vadd_vv, vsetvli_e64m1tama, vzext_vf2, vsetvli_e32mf2tama, vmv_v_x, vsetvli_e64m1tama, vsll_vi, vluxei64_v, vsetvli_e32mf2tama, vadd_vv, vsetvli_e64m1tama, vsub_vv, | +, ?
        Loop control variable: a4(0x003525ba:5d) = a4(0x00352596:10f) + u0x1000001e(0x003525ba:147)
        Loop Local-scope Varnodes: t1(0x003525a2:55), u0x1000001e(0x003525ba:147), a4(0x003525ba:5d), a6(0x003525d4:67), a6(0x00352596:11b), a4(0x003525ba:5d)
```

### analysis

Vector registers need to be saved - or regenerated - across function calls.  In the decompiler window this pattern appears as

```c
lVar2 = -vlenb;
...
vs1r_v(auVar14,(long)auStack_860 + lVar2);
uVar3 = (*pcVar5)(dev,auStack_860,values + (uVar9 & 0xffffffff),(long)iVar1,uVar9 << 0x20,
                  pcVar5);
auVar14 = vl1re64_v((long)auStack_860 + lVar2);
```

* `auStack_860` is the last variable saved at the bottom of the stack, so `auStack_860 - vlenb` refers to a new register save space allocated on the stack across the function call.
* the `vs1r_v` and `vl1re64_v` are whole register store and load instructions.
* the store and load statements could be suppressed entirely,
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

## Unrolled vector sequences

The dpdk-l3fwd binary includes the function `power_pstate_cpufreq_init`

### Features

### Ghidra decompilation (annotated)

```c
undefined8 power_pstate_cpufreq_init(ulong param_1)

{
...
vsetivli_e32m1tama(4);
auVar22 = vle32_v(lVar7 + 0x2ef4390);
auVar22 = vmseq_vx(auVar22,lVar13);
lVar8 = vcpop_m(auVar22);
if (lVar8 == 0) {
  auVar22 = vle32_v(lVar7 + 0x2ef43a0);
  auVar22 = vmseq_vx(auVar22,lVar13);
  lVar8 = vcpop_m(auVar22);
  if (lVar8 == 0) {
    uVar16 = uVar4 - 3;
    uVar3 = uVar16 >> 2;
    if (uVar3 != 2) {
      auVar22 = vle32_v(lVar7 + 0x2ef43b0);
      auVar22 = vmseq_vx(auVar22,lVar13);
      lVar8 = vcpop_m(auVar22);
      if (lVar8 != 0) {
        auVar22 = vid_v();
        auVar22 = vadd_vi(auVar22,0xb);
        uVar15 = vmv_x_s(auVar22);
        goto LAB_ram_009c6740;
      }
      if (uVar3 != 3) {
        auVar22 = vle32_v(lVar7 + 0x2ef43c0);
        auVar22 = vmseq_vx(auVar22,lVar13);
        lVar8 = vcpop_m(auVar22);
        if (lVar8 != 0) {
          auVar22 = vid_v();
          auVar22 = vadd_vi(auVar22,0xf);
          uVar15 = vmv_x_s(auVar22);
          goto LAB_ram_009c6740;
        }
        if (uVar3 != 4) {
          auVar22 = vle32_v(lVar7 + 0x2ef43d0);
          auVar22 = vmseq_vx(auVar22,lVar13);
          lVar8 = vcpop_m(auVar22);
          if (lVar8 != 0) {
            auVar22 = vid_v();
            auVar22 = vadd_vx(auVar22,0x13);
            uVar15 = vmv_x_s(auVar22);
            goto LAB_ram_009c6740;
          }
          if (uVar3 != 5) {
            auVar22 = vle32_v(lVar7 + 0x2ef43e0);
            auVar22 = vmseq_vx(auVar22,lVar13);
            lVar8 = vcpop_m(auVar22);
            if (lVar8 != 0) {
              auVar22 = vid_v();
              auVar22 = vadd_vx(auVar22,0x17);
              uVar15 = vmv_x_s(auVar22);
              goto LAB_ram_009c6740;
            }
            if (uVar3 != 6) {
              auVar22 = vle32_v(lVar7 + 0x2ef43f0);
              auVar22 = vmseq_vx(auVar22,lVar13);
              lVar8 = vcpop_m(auVar22);
              if (lVar8 != 0) {
                auVar22 = vid_v();
                auVar22 = vadd_vx(auVar22,0x1b);
                uVar15 = vmv_x_s(auVar22);
                goto LAB_ram_009c6740;
              }
              if (uVar3 != 7) {
                auVar22 = vle32_v(lVar7 + 0x2ef4400);
                auVar22 = vmseq_vx(auVar22,lVar13);
                lVar8 = vcpop_m(auVar22);
                if (lVar8 != 0) {
                  auVar22 = vid_v();
                  auVar22 = vadd_vx(auVar22,0x1f);
                  uVar15 = vmv_x_s(auVar22);
                  goto LAB_ram_009c6740;
                }
                if (uVar3 != 8) {
                  auVar22 = vle32_v(lVar7 + 0x2ef4410);
                  auVar22 = vmseq_vx(auVar22,lVar13);
                  lVar8 = vcpop_m(auVar22);
                  if (lVar8 != 0) {
                    auVar22 = vid_v();
                    auVar22 = vadd_vx(auVar22,0x23);
                    uVar15 = vmv_x_s(auVar22);
                    goto LAB_ram_009c6740;
                  }
                  if (uVar3 != 9) {
                    auVar22 = vle32_v(lVar7 + 0x2ef4420);
                    auVar22 = vmseq_vx(auVar22,lVar13);
                    lVar8 = vcpop_m(auVar22);
                    if (lVar8 != 0) {
                      auVar22 = vid_v();
                      auVar22 = vadd_vx(auVar22,0x27);
                      uVar15 = vmv_x_s(auVar22);
                      goto LAB_ram_009c6740;
                    }
                    if (uVar3 != 10) {
                      auVar22 = vle32_v(lVar7 + 0x2ef4430);
                      auVar22 = vmseq_vx(auVar22,lVar13);
                      lVar8 = vcpop_m(auVar22);
                      if (lVar8 != 0) {
                        auVar22 = vid_v();
                        auVar22 = vadd_vx(auVar22,0x2b);
                        uVar15 = vmv_x_s(auVar22);
                        goto LAB_ram_009c6740;
                      }
                      if (uVar3 != 0xb) {
                        auVar22 = vle32_v(lVar7 + 0x2ef4440);
                        auVar22 = vmseq_vx(auVar22,lVar13);
                        lVar8 = vcpop_m(auVar22);
                        if (lVar8 != 0) {
                          auVar22 = vid_v();
                          auVar22 = vadd_vx(auVar22,0x2f);
                          uVar15 = vmv_x_s(auVar22);
                          goto LAB_ram_009c6740;
                        }
                        if (uVar3 != 0xc) {
                          auVar22 = vle32_v(lVar7 + 0x2ef4450);
                          auVar22 = vmseq_vx(auVar22,lVar13);
                          lVar8 = vcpop_m(auVar22);
                          if (lVar8 != 0) {
                            auVar22 = vid_v();
                            auVar22 = vadd_vx(auVar22,0x33);
                            uVar15 = vmv_x_s(auVar22);
                            goto LAB_ram_009c6740;
                          }
                          if (uVar3 != 0xd) {
                            auVar22 = vle32_v(lVar7 + 0x2ef4460);
                            auVar22 = vmseq_vx(auVar22,lVar13);
                            lVar8 = vcpop_m(auVar22);
                            if (lVar8 != 0) {
                              auVar22 = vid_v();
                              auVar22 = vadd_vx(auVar22,0x37);
                              uVar15 = vmv_x_s(auVar22);
                              goto LAB_ram_009c6740;
                            }
                            if (uVar3 != 0xe) {
                              auVar22 = vle32_v(lVar7 + 0x2ef4470);
                              auVar22 = vmseq_vx(auVar22,lVar13);
                              lVar8 = vcpop_m(auVar22);
                              if (lVar8 != 0) {
                                auVar22 = vid_v();
                                auVar22 = vadd_vx(auVar22,0x3b);
                                uVar15 = vmv_x_s(auVar22);
                                goto LAB_ram_009c6740;
                              }
                              if (uVar3 != 0xf) {
                                auVar22 = vle32_v(lVar7 + 0x2ef4480);
                                auVar22 = vmseq_vx(auVar22,lVar13);
                                lVar7 = vcpop_m(auVar22);
                                if (lVar7 != 0) {
                                  auVar22 = vid_v();
                                  auVar22 = vadd_vx(auVar22,0x3f);
                                  uVar15 = vmv_x_s(auVar22);
                                  goto LAB_ram_009c6740;
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
}
```

The corresponding source code *appears* to be:

```c
for (i = 0; i < pi->nb_freqs; i++) {
    if (freq_conv == pi->freqs[i]) {
            pi->curr_idx = i;
            break;
    }
}
```

The source code suggests this vector sequence is a simple linear search for a 32 bit uint32_t value, with the matching index stored in `pi->curr_idx`.  The maximum size of `pi->freqs` is a constant value
known to the compiler, 64 elements of 4 bytes each.

* The compiler unrolled the loop into a set of 16 vector sequences, each processing 4 elements of 32 bits each.  The minimum vector register size must be 128 bits.
* Each sequence consists of `vle32_v`, `vmseq_vx`, and `vcpop_m` instructions to count the number of matches within that 4 element slice.
* If a match is found, an index is computed with a sequence of `vid_v()`, `vadd_vx`, and `vmv_x_s` instructions.

>Warning: The vectorized index computation looks buggy, as it apparently misidentifies the matching element index value and returns either the first or the last index in each 4 element slice.

This binary exemplar was compiled with `-std=c11 -O3 -march=rv64gcv`.  Initialization code like this would be very unlikely to benefit from loop unrolling and `-O3` optimization.  If this binary were
built as part of a product, it would be much more likely to be built with `-std=c11 -O2 -march=rv64gcv` and a fully released version of gcc.  When this DPDK exemplar is recompiled with `-O2` optimization
the loops are neither unrolled nor vectorized.

## Vectorization with -O2

Many of the more complex vectorization sequences occur only with `-O3` optimization and in functions that are not worth optimizing.  Let's switch to the `dpdk-l3fwd` exemplar compiled with `-O2` optimization
and look for vectorized sequences closer to the 'hot' functions.

The function `acl_merge_trie` includes these vector loops (annotated):

```c
      vsetvli_e32m1tama(0);
      auVar25 = vmv_v_i(0);
      auVar26 = vmv_v_i(2);
      do {
        lVar20 = vsetvli_e32m1tumu(uVar7);          // note the unmasked and tail elements are to be *unchanged*
        auVar28 = vle32_v(lVar19);                  // load X (auVar28)
        auVar29 = vle32_v(lVar12);                  // load Y (auVar29)
        uVar7 = uVar7 - lVar20;                     // count--
        lVar12 = lVar12 + lVar20 * 4;
        lVar19 = lVar19 + lVar20 * 4;
        auVar27 = vmslt_vv(auVar29,auVar28);        // M1 = Y<X
        auVar29 = vmsne_vv(auVar29,auVar28);        // M2 = Y!=X
        auVar28 = vmerge_vim(auVar26,1,auVar27);    // T1 = M1 ? 1 : 2
        auVar27 = vmv1r_v(auVar29);                 //
        auVar25 = vor_vv(auVar28,auVar25,auVar27);  // Z = T1 | Z if M2
      } while (uVar7 != 0);
      vsetvli_e32m1tama(0);
      auVar26 = vmv_s_x(0);
      auVar25 = vredor_vs(auVar25,auVar26);
      uVar7 = vmv_x_s(auVar25);                     // uVar7 = or reduction of Z
```

```c
long acl_merge_trie(long param_1,long param_2,long param_3,long param_4,long *param_5)
{
lVar10 = -vlenb;
...
vsetivli_e32m1tama(4);
auVar25 = vmv_s_x(0);
vs1r_v(auVar25,auStack_c0 + lVar10);
uVar19 = 0;
*(long *)((long)auStack_128 + lVar10 + 8) = lVar16;
*(long *)((long)auStack_128 + lVar10) = lVar18;
lVar16 = 0;
do {
  lVar18 = uVar19 * 0x28 + *(long *)(param_3 + 0x40);
  if (*(long *)(*(long *)(param_3 + 0x40) + lVar16 + 0x20) != 0) {
    auVar25 = vle32_v(puVar20);
    auVar26 = vle32_v(auStack_a0 + vlenb + lVar10);
    auVar29 = vle32_v(lVar18);
    auVar27 = vle32_v(lVar18 + 0x10);
    auVar25 = vnot_v(auVar25);
    auVar26 = vnot_v(auVar26);
    auVar25 = vand_vv(auVar25,auVar29);
    auVar26 = vand_vv(auVar26,auVar27);
    vse32_v(auVar25,auStack_90 + vlenb + lVar10);
    vse32_v(auVar26,auStack_80 + vlenb + lVar10);
    auVar25 = vor_vv(auVar25,auVar26);
    auVar26 = vl1re32_v(auStack_c0 + lVar10);
    auVar25 = vredor_vs(auVar25,auVar26);
    lVar11 = vmv_x_s(auVar25);
    if (lVar11 != 0) {
      acl_add_ptr.isra.0(param_1,lVar7,*(undefined8 *)(lVar18 + 0x20),
                         auStack_90 + vlenb + lVar10);
      uVar5 = (ulong)*(int *)(param_3 + 0x30);
      vsetivli_e32m1tama(4);
    }
  }
  uVar19 = (ulong)((int)uVar19 + 1);
  lVar16 = lVar16 + 0x28;
} while (uVar19 < uVar5);
...
}
```

This function'd decompilation is especially confusing because of Ghidra's inability to track stack (automatic) variables.  The code provides for a vector register save area
on the stack with:

```as
  csrr t0,vlenb
  sub  sp,sp,t0
```

Ghidra treats `vlenb` as a symbol and variable, with an indeterminate value.  The compiler knows how to make runtime adjustments to locate scalar stack variables, but Ghidra does not.
One such correction is:

```as
  csrr a0,vlenb
  addi a1,a0,0xa0  ; get the relative stack offset of auStack_a0 after allowing for the vlenb vector saave area
  add  s10,sp,a1   ; s10 now points to auStack_a0
```
