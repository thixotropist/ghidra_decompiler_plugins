---
title: RISC-V intrinsic functions
description: How many unique RISC-V C intrinsic functions are there?
weight: 30
---

## User Request
How many unique RISC-V C intrinsic functions are there?

---

## Response

There is no single static number of RISC-V C intrinsic functions because the intrinsic specification is **generative**, expanding programmatically based on data types, vector register groupings, masking, and tail/mask policies.

However, depending on how they are counted and which extensions are enabled, the total number of unique intrinsic functions in modern compiler header files (`<riscv_vector.h>`, cryptography headers, etc.) breaks down as follows:

---

### Quick Summary

| Category | Non-Overloaded (Explicit Types) | Overloaded (Generic API) |
| :--- | :--- | :--- |
| **RISC-V Vector Extension (`v`)** | **~80,000 to 130,000+** | **~10,000 to 15,000** |
| **Scalar Cryptography (`Zkn`, `Zks`, etc.)** | **~60 to 120** | N/A |
| **Bit Manipulation (`Zba`, `Zbb`, `Zbc`, `Zbs`)** | **~50 to 100** | N/A |
| **Packed SIMD / DSP (`P` Extension draft)** | **~200 to 400** | N/A |
| **Total Across All Extensions** | **~80,000–130,000+** | **~10,000–15,000** |

---

### Why is the Vector Count So Massive? (Combinatorial Explosion)

The **RISC-V Vector C Intrinsic Specification** (`rvv-intrinsic-doc`) accounts for over **99%** of all RISC-V intrinsics.

While the base RISC-V Vector ISA defines roughly 400 vector instructions, each instruction expands combinatorially into hundreds of distinct C function signatures based on:

1. **Element Widths (SEW):** `int8`, `int16`, `int32`, `int64`, `uint8`, `uint16`, `uint32`, `uint64`, `float16`, `float32`, `float64`, `bfloat16`.
2. **Register Groupings (LMUL):** `m1`, `m2`, `m4`, `m8`, `mf2`, `mf4`, `mf8`.
3. **Masking:** Unmasked vs. Masked (`_m`).
4. **Tail & Mask Policies:**
   * Tail Agnostic / Tail Undisturbed (`_ta`, `_tu`)
   * Mask Agnostic / Mask Undisturbed (`_ma`, `_mu`)
5. **Segmented Tuple Types:** Segment loads/stores (`vldseg`, `vstseg`) across tuple groupings (2 to 8 registers).


#### Example: The `vadd.vv` instruction
A simple vector addition (`vadd.vv`) generates dozens of explicit C intrinsic signatures such as:
* `vint32m1_t __riscv_vadd_vv_i32m1(vint32m1_t op1, vint32m1_t op2, size_t vl);`
* `vint32m1_t __riscv_vadd_vv_i32m1_m(vbool32_t mask, vint32m1_t op1, vint32m1_t op2, size_t vl);`
* `vint32m1_t __riscv_vadd_vv_i32m1_tu(vint32m1_t maskedoff, vint32m1_t op1, vint32m1_t op2, size_t vl);`
* ... (repeated across all integer widths, LMUL ratios, and policy combinations).

---

### Overloaded vs. Non-Overloaded Intrinsics

To make code readable, RISC-V provides an **overloaded API**:
* **Explicit (Non-overloaded):** Full function names specifying types and LMUL explicitly (e.g., `__riscv_vadd_vv_i32m1`). This set contains **80,000+** functions.
* **Overloaded:** Shortened generic names resolved by the compiler based on argument types (e.g., `__riscv_vadd`). This reduces the developer-facing function set to roughly **10,000–15,000** unique overloaded names.

---

### Non-Vector Intrinsics

Compared to vector intrinsics, scalar RISC-V intrinsics are concise and closer in number to traditional architectures:

* **Bit Manipulation (`Zba`, `Zbb`, `Zbc`, `Zbs`):** Provides functions for bit counting, rotation, and single-bit operations (e.g., `__builtin_riscv_clz`, `__builtin_riscv_orc_b`).
* **Scalar Cryptography (`Zk` extensions):** Acceleration for AES, SHA-256, SHA-512, SM3, and SM4 (e.g., `__builtin_riscv_aes64ks1i`).
* **Packed SIMD (`P` extension):** Operates on sub-word integer data in standard 32/64-bit GPRs for DSP workloads.

---

### How to Count Intrinsics in Your Toolchain

Because the number varies depending on GCC/LLVM versions and which extension headers are installed, you can count the exact number of defined intrinsics on your machine:

```bash
# Count explicit RISC-V vector intrinsic prototypes in GCC/Clang header
grep -E '^\s*__riscv_' $(llvm-config --includedir)/riscv_vector.h | wc -l

# Count unique overloaded function names
grep -oh '__riscv_[a-z0-9_]*' <riscv_vector.h> | sort -u | wc -l