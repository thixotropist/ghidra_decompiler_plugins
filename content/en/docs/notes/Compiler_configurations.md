---
title: Compiler configurations
description: Vector optimizations can depend heavily on the command line flags given to the compiler
weight: 150
---

This project explores ways to evolve Ghidra's decompiler in the same direction as - and hopefully as rapidly as - emerging processor, micro-architecture, and compiler evolutions.
For that reason we tend to use the latest gcc versions and the most aggressive available optimizations.  Current production code is likely to be much less aggressive overall, perhaps with
known hotspot functions selectively optimized - and tested - more aggressively.

Most binary exemplars used in this project were compiled with gcc version 15.2.0 (built in 2025) and with `-march=rva64gcv -O3`, enabling vector instructions and aggressive optimization.

## additional gcc 15.2 optimizations enabled by O3

* `-fgcse-after-reload`
* `-fipa-cp-clone`
* `-floop-interchange`
* `-floop-unroll-and-jam`
* `-fpeel-loops`
* `-fpredictive-commoning`
* `-fsplit-loops`
* `-fsplit-paths`
* `-ftree-loop-distribution`
* `-ftree-partial-pre`
* `-funroll-completely-grow-size`
* `-funswitch-loops`
* `-fvect-cost-model=[unlimited|dynamic|cheap|very-cheap]` 	dynamic (O2 version is `very-cheap`)
* `-fversion-loops-for-strides`

>Note: gcc 16.1.1 adds some new optimizations but apparently does not promote any gcc 15 `-O3` optimizations to enabled status.

## dpdk main branch optimizations

The `dpdk` source includes RISC-V vector-optimized C functions using RISC-V C intrinsics.

For example, see `lib/acl/acl_run_rvv.h`, which seeks to parallelize trie traversal for path and access control decisions.
Curiously, this code hardwires the vector register size to 128 bits, the minimum supported by the `rva23` profile.  All other
vectorizations are performed by the compiler.

## compare O2 and O3 exemplars

| feature | with -O2 | with -O3|
| :------ | -----: | -----: |
| instruction count | 2644137 | 3049511 |
| function count | 24197 | 23422 |
| text size | 0x78a94a | 0x8ccbee |
| vector_memcpy | 6487 | 7740 |
| vector_memset | 1704 | 1930 |
| vector_strlen | 193 | 237 |
| vector_strcmp | 720 | 841 |

The four basic `vector_*` transforms appear at about the same frequency in both O2 and O3 optimization
levels, allowing for the O3 habit of expanding code size by about 15%.

More radical loop vectorizations may be disabled with -O2 optimizations.

## Two dimensional compiler comparison

How much does a known complex transform change with optimization level and compiler release?

The sample C function:

```c
void test_1_ref(unsigned long long *in, unsigned long long *out, unsigned int size)
{
    int i;
    int upper_index = size - 1;
    for (i=0; i < size; i++) {
        out[i] = in[upper_index - i];
    }
}
```

Build with GCC 15.2 and `-O2`:
`/opt/riscv/sysroot/bin/riscv64-linux-gnu-gcc -c -O2 -march=rv64gcv test_1_ref.c -o test_1_ref_15_2_O2.o`:

Text length = 0x24 bytes.

```c
do {
    uVar4 = *puVar1;
    puVar3 = puVar2 + 1;
    puVar1 = puVar1 + -1;
    *puVar2 = uVar4;
    puVar2 = puVar3;
} while (puVar3 != param_2 + (param_3 & 0xffffffff));
```

Build with GCC 16.1 and `-O2`:
`riscv64-linux-gnu-gcc  -c -O2 -march=rv64gcv test_1_ref.c -o test_1_ref_16_1_O2.o`:

Text length = 0x24 bytes.

```c
    do {
      uVar4 = *puVar1;
      puVar3 = puVar2 + 1;
      puVar1 = puVar1 + -1;
      *puVar2 = uVar4;
      puVar2 = puVar3;
    } while (puVar3 != param_2 + (param_3 & 0xffffffff));
```

Build with GCC 15.2 and `-O3`:
`/opt/riscv/sysroot/bin/riscv64-linux-gnu-gcc -c -O3 -march=rv64gcv test_1_ref.c -o test_1_ref_15_2_O3.o`:

Text length = 0xc2 bytes.

```c
if (param_3 != 0) {
uVar5 = (ulong)((int)param_3 + -1);
if (0xc < uVar5) {
    if (((ulong)(long)((int)(vlenb >> 3) + -1) <= uVar5) &&
        ((lVar6 = uVar5 * 8 + 8,
        param_2 + (param_3 & 0xffffffff) <=
        (undefined8 *)(uVar5 * 8 + (param_3 & 0xffffffff) * -8 + 8 + param_1) ||
        ((undefined8 *)(param_1 + lVar6) <= param_2)))) {
    vsetvli_e64m1tama(0);
    auVar10 = vid_v();
    auVar10 = vrsub_vx(auVar10,(vlenb >> 3) - 1);
    lVar6 = (lVar6 - vlenb) + param_1;
    iVar1 = (int)(vlenb >> 3);
    uVar7 = 0;
    puVar3 = param_2;
    do {
        auVar9 = vl1re64_v(lVar6);
        uVar7 = (ulong)((int)uVar7 + iVar1);
        lVar6 = lVar6 - vlenb;
        auVar9 = vrgather_vv(auVar9,auVar10);
        vs1r_v(auVar9,puVar3);
        puVar3 = (undefined8 *)((long)puVar3 + vlenb);
    } while (uVar7 <= (ulong)(long)((int)param_3 - iVar1));
    if (param_3 == uVar7) {
        return;
    }
    puVar3 = (undefined8 *)(param_1 + uVar5 * 8 + uVar7 * -8);
    param_2 = param_2 + uVar7;
    do {
        uVar4 = *puVar3;
        uVar7 = (ulong)((int)uVar7 + 1);
        puVar3 = puVar3 + -1;
        *param_2 = uVar4;
        param_2 = param_2 + 1;
    } while (uVar7 < param_3);
    return;
    }
}
puVar8 = (undefined8 *)(param_1 + uVar5 * 8);
puVar3 = param_2;
do {
    uVar4 = *puVar8;
    puVar2 = puVar3 + 1;
    puVar8 = puVar8 + -1;
    *puVar3 = uVar4;
    puVar3 = puVar2;
} while (puVar2 != param_2 + (param_3 & 0xffffffff));
}
return;
```

Build with GCC 16.1 and `-O3`:
`riscv64-linux-gnu-gcc  -c -O3 -march=rv64gcv test_1_ref.c -o test_1_ref_16_1_O3.o`:

Text length = 0xd0 bytes.

```c
if (param_3 != 0) {
lVar10 = (vlenb >> 3) - 1;
uVar5 = (ulong)((int)param_3 + -1);
uVar7 = param_3 & 0xffffffff;
lVar9 = uVar5 * 8;
if ((uVar5 < 0xd || uVar5 < (ulong)(long)(int)lVar10) ||
    (lVar6 = (uVar5 + 1) * 8,
    (undefined8 *)(lVar9 + uVar7 * -8 + 8 + param_1) < param_2 + uVar7 &&
    param_2 < (undefined8 *)(param_1 + lVar6))) {
    puVar8 = (undefined8 *)(param_1 + lVar9);
    puVar3 = param_2;
    do {
    uVar4 = *puVar8;
    puVar2 = puVar3 + 1;
    puVar8 = puVar8 + -1;
    *puVar3 = uVar4;
    puVar3 = puVar2;
    } while (puVar2 != param_2 + uVar7);
}
else {
    vsetvli_e64m1tama(0);
    auVar12 = vid_v();
    auVar12 = vrsub_vx(auVar12,lVar10);
    lVar6 = param_1 + (lVar6 - vlenb);
    auVar12 = vand_vx(auVar12,lVar10);
    uVar7 = 0;
    iVar1 = (int)(vlenb >> 3);
    puVar3 = param_2;
    do {
    auVar11 = vl1re64_v(lVar6);
    uVar7 = (ulong)((int)uVar7 + iVar1);
    lVar6 = lVar6 - vlenb;
    auVar11 = vrgather_vv(auVar11,auVar12);
    vs1r_v(auVar11,puVar3);
    puVar3 = (undefined8 *)((long)puVar3 + vlenb);
    } while (uVar7 <= (ulong)(long)((int)param_3 - iVar1));
    if (param_3 != uVar7) {
    puVar3 = (undefined8 *)(param_1 + lVar9 + uVar7 * -8);
    param_2 = param_2 + uVar7;
    do {
        uVar4 = *puVar3;
        uVar7 = (ulong)((int)uVar7 + 1);
        puVar3 = puVar3 + -1;
        *param_2 = uVar4;
        param_2 = param_2 + 1;
    } while (uVar7 < param_3);
    return;
    }
}
}
return;
```

### summary

* With the `-O2` optimization level neither the 15.2 nor 16.1 gcc compiler tries to optimize this code.
* With the `-O3` optimization level both the 15.2 nor 16.1 gcc compiler vectorizes this code by expanding it 6 fold.  The different gcc versions use similar but slightly different transform patterns.
