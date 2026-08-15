---
title: Analysis of complex loops
description: Complex loops - especially those using RISC-V intrinsics - offer analysis challenges
weight: 200
---

Most of the previous work deals with recognizing and simplifying simple loops dominated by RISC-V vector instructions.
These simple loops are likely either expansions of compiler builtins like `builtin_memcpy` or auto-vectorizations
of simple `for` loops.

The current plugin fails to process complex loops at all, providing little help for the user in understanding how
relevant the loop may be.  This page explores possible analytic plugin tools to provide that help.

Examples of complex loops include:
1. expansions of compiler builtins like `builtin_strncpy`, where the main loop includes two conditional branches
   and therefore results in two Ghidra blocks.
2. loops that include a non-inlined function call.  Such loops can be especially hard to analyze if the compiler
   needs to save and restore one or more vector registers to the stack across such function calls.
3. loops that are auto-vectorized into multiple blocks to optimize for vector lengths that are unknown at compile time
   and have an unknown relationship with the current hart's vector register length.
4. loops that are too complex for auto-vectorization but are worth manual vectorization using RISC-V
   [intrinsics](https://docs.riscv.org/reference/vector-c-intrinsics/_attachments/v-intrinsic-spec.pdf).
5. loops that benefit enough from vendor specific optimizations to be coded in RISC-V assembly language,
   likely with loop unrolling and vector grouping choices tuned for a specific micro-architecture.
       * For example, see the definition of `memcpy1d` within SpacemiT's tuning of
         [ggml](https://github.com/ggml-org/llama.cpp/blob/master/ggml/src/ggml-cpu/spacemit/rvv_kernels.cpp)

## Complex loops using RISC-V C intrinsics

We'll start with a RISC-V Inference Engine example of the fourth type above - a vector dot product function optimized
for the RISC-V vector instruction set.  This function is likely one of the 'hottest' functions in any IE application.

>Why would this kind of function be of any interest to Ghidra users?  It doesn't appear to be vulnerable to any of the
>traditional risks.  On the other hand, if an adversary was able to modify the code they may insert a selective performance reduction
>to might degrade key visual processing subsystems.
>
>Another big use-case for Ghidra analysis of such functions is to locate subtle bugs leading to likely data corruption.
>See [AI survey of gcc RISC-V intrinsics bugs]({{< relref "Llm_surveys/Gcc16_riscv_bugs.md" >}}) for an AI-generated
>summary of a likely buggy compilation.

### Generic and RVV source code

The generic (processor independent) source code for the sample function includes:

```c
// QK_K = super-block size
#define QK_K 256
// 4-bit quantization
// 8 blocks of 32 elements each
// weight is represented as x = a * q + b
// Effectively 4.5 bits per weight
typedef struct {
    GGML_EXTENSION union {
        struct {
            ggml_half d;    // super-block scale for quantized scales
            ggml_half dmin; // super-block scale for quantized mins
        } GGML_COMMON_AGGR_S;
        ggml_half2 dm;
    } GGML_COMMON_AGGR_U;
    uint8_t scales[K_SCALE_SIZE]; // scales and mins, quantized with 6 bits
    uint8_t qs[QK_K/2];           // 4--bit quants
} block_q4_K;

// This is only used for intermediate quantization and dot products
typedef struct {
    float   d;              // delta
    int8_t  qs[QK_K];       // quants
    int16_t bsums[QK_K/16]; // sum of quants in groups of 16
} block_q8_K;

void ggml_vec_dot_q4_K_q8_K_generic(int n, float * GGML_RESTRICT s, size_t bs, const void * GGML_RESTRICT vx, size_t bx, const void * GGML_RESTRICT vy
, size_t by, int nrc) {
    assert(n % QK_K == 0);
    assert(nrc == 1);
    UNUSED(nrc);
    UNUSED(bx);
    UNUSED(by);
    UNUSED(bs);

    const block_q4_K * GGML_RESTRICT x = vx;
    const block_q8_K * GGML_RESTRICT y = vy;

    const int nb = n / QK_K;

    static const uint32_t kmask1 = 0x3f3f3f3f;
    static const uint32_t kmask2 = 0x0f0f0f0f;
    static const uint32_t kmask3 = 0x03030303;

    uint32_t utmp[4];

    const uint8_t * scales = (const uint8_t*)&utmp[0];
    const uint8_t * mins   = (const uint8_t*)&utmp[2];

    int8_t  aux8[QK_K];
    int16_t aux16[8];
    float   sums [8];
    int32_t aux32[8];
    memset(sums, 0, 8*sizeof(float));

    float sumf = 0;
    for (int i = 0; i < nb; ++i) {
        const uint8_t * GGML_RESTRICT q4 = x[i].qs;
        const  int8_t * GGML_RESTRICT q8 = y[i].qs;
        memset(aux32, 0, 8*sizeof(int32_t));
        int8_t * GGML_RESTRICT a = aux8;
        for (int j = 0; j < QK_K/64; ++j) {
            for (int l = 0; l < 32; ++l) a[l] = (int8_t)(q4[l] & 0xF);
            a += 32;
            for (int l = 0; l < 32; ++l) a[l] = (int8_t)(q4[l]  >> 4);
            a += 32; q4 += 32;
        }
        memcpy(utmp, x[i].scales, 12);
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4);
        const uint32_t uaux = utmp[1] & kmask1;
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4);
        utmp[2] = uaux;
        utmp[0] &= kmask1;

        int sumi = 0;
        for (int j = 0; j < QK_K/16; ++j) sumi += y[i].bsums[j] * mins[j/2];
        a = aux8;
        int is = 0;
        for (int j = 0; j < QK_K/32; ++j) {
            int32_t scale = scales[is++];
            for (int l = 0; l < 8; ++l) aux16[l] = q8[l] * a[l];
            for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
            q8 += 8; a += 8;
            for (int l = 0; l < 8; ++l) aux16[l] = q8[l] * a[l];
            for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
            q8 += 8; a += 8;
            for (int l = 0; l < 8; ++l) aux16[l] = q8[l] * a[l];
            for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
            q8 += 8; a += 8;
            for (int l = 0; l < 8; ++l) aux16[l] = q8[l] * a[l];
            for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
            q8 += 8; a += 8;
        }
        const float d = GGML_CPU_FP16_TO_FP32(x[i].d) * y[i].d;
        for (int l = 0; l < 8; ++l) sums[l] += d * aux32[l];
        const float dmin = GGML_CPU_FP16_TO_FP32(x[i].dmin) * y[i].d;
        sumf -= dmin * sumi;
    }
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    *s = sumf;
}
```

Context helps understand what is going on with this not-so-simple dot product:
* The Q4_K quantization format defines blocks of Inference Engine 4 bit weights, grouped with scale factors
  and minima
    * The Q8_K quantization format accumulates the resulting sum with double the precision of individual elements.
* The block sizes are tuned with typical vector register lengths in mind
* all interior loops - including memcpy and memset loops - have a known number of iterations.
* The superblock calculation loop is unrolled or sliced into four staggered operations
* some of the scale factors are encoded as half-precision floating point numbers, if the underlying processor
  supports that format.

If the compiler flags indicate that the CPU hart is a RISC-V core supporting the RISC-V vector extensions and with a Vector Length register of exactly 256 bits,
then this source is used instead of the generic source above.

```c
static NOINLINE void ggml_vec_dot_q4_K_q8_K_vl256(int n, float * GGML_RESTRICT s, size_t bs, const void * GGML_RESTRICT vx, size_t bx, const void * GGML_RESTRICT vy, size_t by, int nrc) {
    assert(n % QK_K == 0);
    assert(nrc == 1);
    UNUSED(nrc);
    UNUSED(bx);
    UNUSED(by);
    UNUSED(bs);

    const block_q4_K * GGML_RESTRICT x = vx;
    const block_q8_K * GGML_RESTRICT y = vy;

    const int nb = n / QK_K;

    static const uint32_t kmask1 = 0x3f3f3f3f;
    static const uint32_t kmask2 = 0x0f0f0f0f;
    static const uint32_t kmask3 = 0x03030303;

    uint32_t utmp[4];

    const uint8_t * scales = (const uint8_t*)&utmp[0];
    const uint8_t * mins   = (const uint8_t*)&utmp[2];

    float sumf = 0;
    for (int i = 0; i < nb; ++i) {
        size_t vl = 8;

        const float d = y[i].d * GGML_CPU_FP16_TO_FP32(x[i].d);
        const float dmin = y[i].d * GGML_CPU_FP16_TO_FP32(x[i].dmin);

        vint16mf2_t q8sums_0 = __riscv_vlse16_v_i16mf2(y[i].bsums, 4, vl);
        vint16mf2_t q8sums_1 = __riscv_vlse16_v_i16mf2(y[i].bsums+1, 4, vl);
        vint16mf2_t q8sums   = __riscv_vadd_vv_i16mf2(q8sums_0, q8sums_1, vl);

        memcpy(utmp, x[i].scales, 12);
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4);
        const uint32_t uaux = utmp[1] & kmask1;
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4);
        utmp[2] = uaux;
        utmp[0] &= kmask1;

        vuint8mf4_t mins8  = __riscv_vle8_v_u8mf4(mins, vl);
        vint16mf2_t v_mins = __riscv_vreinterpret_v_u16mf2_i16mf2(__riscv_vzext_vf2_u16mf2(mins8, vl));
        vint32m1_t  prod   = __riscv_vwmul_vv_i32m1(q8sums, v_mins, vl);

        vint32m1_t sumi = __riscv_vredsum_vs_i32m1_i32m1(prod, __riscv_vmv_v_x_i32m1(0, 1), vl);
        sumf -= dmin * __riscv_vmv_x_s_i32m1_i32(sumi);

        const uint8_t * GGML_RESTRICT q4 = x[i].qs;
        const int8_t  * GGML_RESTRICT q8 = y[i].qs;

        vl = 32;

        int32_t sum_1 = 0;
        int32_t sum_2 = 0;

        vint16m1_t vzero = __riscv_vmv_v_x_i16m1(0, 1);
        for (int j = 0; j < QK_K/64; ++j) {
            // load Q4
            vuint8m1_t q4_x = __riscv_vle8_v_u8m1(q4, vl);

            // load Q8 and multiply it with lower Q4 nibble
            vint8m1_t  q8_0 = __riscv_vle8_v_i8m1(q8, vl);
            vint8m1_t  q4_0 = __riscv_vreinterpret_v_u8m1_i8m1(__riscv_vand_vx_u8m1(q4_x, 0x0F, vl));
            vint16m2_t qv_0 = __riscv_vwmul_vv_i16m2(q4_0, q8_0, vl);
            vint16m1_t vs_0 = __riscv_vredsum_vs_i16m2_i16m1(qv_0, vzero, vl);

            sum_1 += __riscv_vmv_x_s_i16m1_i16(vs_0) * scales[2*j+0];

            // load Q8 and multiply it with upper Q4 nibble
            vint8m1_t  q8_1 = __riscv_vle8_v_i8m1(q8+32, vl);
            vint8m1_t  q4_1 = __riscv_vreinterpret_v_u8m1_i8m1(__riscv_vsrl_vx_u8m1(q4_x, 0x04, vl));
            vint16m2_t qv_1 = __riscv_vwmul_vv_i16m2(q4_1, q8_1, vl);
            vint16m1_t vs_1 = __riscv_vredsum_vs_i16m2_i16m1(qv_1, vzero, vl);

            sum_2 += __riscv_vmv_x_s_i16m1_i16(vs_1) * scales[2*j+1];

            q4 += 32;    q8 += 64;

        }

        sumf += d*(sum_1 + sum_2);

    }
    *s = sumf;
}

```

Context helps here too:
* only a single loop is needed to complete the inner dot product, with four iterations through the loop.
  This inner loop can therefore be striped or strip-mined by the compiler.
* the Q4_K weights are packed two per byte, with vector mask and shift operations used to process
  the nibbles separately.
* LMUL = 2 is used during the reduction operations, allowing for 16 bit summation results to
  spread out over two grouped vector registers.

The use of RISC-V intrinsic functions provides clear optimizations at some cost in clarity - the
RISC-V intrinsic functions specification PDF is over 4000 pages long, with upwards of 100,000
type-specific functions defined.

### Ghidra decompilations

Build this function with compiler flags `-march=rv64gcv_zfh_zvfh_zba_zicbop -mabi=lp64d -fno-tree-vectorize -fno-tree-loop-vectorize -O3 -DNDEBUG -std=gnu11`
and present it to Ghidra.

The generic form of the function is too complex for GCC version 16.2 to autovectorize with the given compilation flags.  A single
`builtin_memcpy` operation is emitted and implemented as three vector instructions.

The RISC-V form with C intrinsics decompiles as:

```c
void ggml_vec_dot_q4_K_q8_K_vl256.isra.0(long param_1,float *param_2,long param_3,long param_4)

{
  float *pfVar1;
  ushort *puVar2;
  ushort *puVar3;
  ulong uVar4;
  undefined8 uVar5;
  uint uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  undefined8 uVar12;
  ulong uVar13;
  undefined8 uVar14;
  undefined8 uVar15;
  int iVar16;
  float fVar17;
  undefined1 auVar18 [32];
  undefined1 auVar19 [32];
  undefined1 auVar20 [32];
  undefined1 auVar21 [32];
  undefined1 auVar22 [32];
  undefined1 auVar23 [32];
  undefined1 auVar24 [32];
  undefined1 auVar25 [32];
  undefined1 auVar26 [32];
  undefined1 auVar27 [32];
  undefined1 auVar28 [32];
  undefined1 auVar29 [32];
  undefined1 auVar30 [32];
  undefined1 auVar31 [32];
  undefined1 auVar32 [32];
  undefined1 auVar33 [32];
  undefined1 auVar34 [32];
  undefined1 auVar35 [32];
  undefined1 auVar36 [32];
  undefined1 auVar37 [32];
  undefined1 auVar38 [32];
  uint local_70;
  uint uStack_6c;
  uint auStack_68 [4];

  if (0xff < param_1) {
    vsetivli_e32m1tama(1);
    fVar17 = 0.0;
    auVar29 = vmv_v_i(0);
    vsetivli_e16m1tama(1);
    auVar18 = vmv_v_i(0);
    param_4 = param_4 + 0x104;
    param_3 = param_3 + 4;
    iVar16 = 0;
    vsetivli_e8m1tama(0xc);
    do {
      auVar21 = vle8_v(param_3);
      vsetivli_e16mf2tama(8);
      auVar20 = vlse16_v(param_4 + 2,4);
      auVar32 = vlse16_v(param_4,4);
      vsetvli_e8m1tama(0x20);
      auVar19 = vle8_v(param_3 + 0xc);
      vsetivli_e8m1tama(0xc);
      vse8_v(auVar21,&local_70);
      vsetvli_e8m1tama(0x20);
      auVar22 = vle8_v(param_3 + 0x4c);
      vsetivli_e16mf2tama(8);
      auVar33 = vadd_vv(auVar32,auVar20);
      vsetvli_e8m1tama(0x20);
      auVar20 = vle8_v(param_3 + 0x2c);
      auVar21 = vle8_v(param_3 + 0x6c);
      uVar4 = (ulong)(int)auStack_68[0];
      auVar30 = vle8_v(param_4 + -0xe0);
      auVar26 = vle8_v(param_4 + -0xa0);
      auVar24 = vle8_v(param_4 + -0x100);
      auVar25 = vle8_v(param_4 + -0xc0);
      auVar38 = vle8_v(param_4 + -0x80);
      auVar32 = vle8_v(param_4 + -0x60);
      auVar36 = vle8_v(param_4 + -0x20);
      auVar35 = vle8_v(param_4 + -0x40);
      auVar31 = vsrl_vi(auVar19,4);
      auVar27 = vsrl_vi(auVar20,4);
      auStack_68[0] = uStack_6c & 0x3f3f3f3f;
      auVar23 = vsrl_vi(auVar22,4);
      auVar19 = vand_vi(auVar19,0xf);
      auVar20 = vand_vi(auVar20,0xf);
      auVar22 = vand_vi(auVar22,0xf);
      auVar28 = vand_vi(auVar21,0xf);
      auVar37 = vsrl_vi(auVar21,4);
      vsetivli_e8mf4tama(8);
      auVar34 = vle8_v(auStack_68);
      vsetvli_e8m1tama(0x20);
      auVar30 = vwmul_vv(auVar31,auVar30);
      auVar26 = vwmul_vv(auVar27,auVar26);
      auVar31 = vwmul_vv(auVar19,auVar24);
      auVar24 = vwmul_vv(auVar20,auVar25);
      auVar32 = vwmul_vv(auVar23,auVar32);
      auVar19 = vwmul_vv(auVar28,auVar35);
      auVar21 = vwmul_vv(auVar22,auVar38);
      auVar20 = vwmul_vv(auVar37,auVar36);
      vsetvli_e16m2tama(0);
      auVar27 = vredsum_vs(auVar30,auVar18);
      auVar26 = vredsum_vs(auVar26,auVar18);
      auVar25 = vredsum_vs(auVar24,auVar18);
      auVar22 = vredsum_vs(auVar21,auVar18);
      auVar24 = vredsum_vs(auVar31,auVar18);
      auVar23 = vredsum_vs(auVar32,auVar18);
      vsetivli_e16mf2tama(8);
      auVar32 = vzext_vf2(auVar34);
      vsetvli_e16m2tama(0x20);
      uVar13 = (long)(int)local_70 & 0x3f3f3f3f;
      auVar19 = vredsum_vs(auVar19,auVar18);
      auVar21 = vredsum_vs(auVar20,auVar18);
      vsetivli_e16mf2tama(8);
      uVar4 = (ulong)(long)(int)local_70 >> 2 & 0x30303030 | uVar4 & 0xf0f0f0f;
      uVar10 = vmv_x_s(auVar27);
      uVar8 = vmv_x_s(auVar26);
      auVar20 = vwmul_vv(auVar33,auVar32);
      uVar7 = vmv_x_s(auVar25);
      uVar15 = vmv_x_s(auVar24);
      vsetvli_e32m1tama(0);
      auVar20 = vredsum_vs(auVar20,auVar29);
      uVar6 = local_70 & 0x3f;
      vsetivli_e16m1tama(0);
      uVar14 = vmv_x_s(auVar23);
      uVar12 = vmv_x_s(auVar22);
      vsetivli_e32m1tama(0);
      uVar5 = vmv_x_s(auVar20);
      vsetivli_e16m2tama(0xc);
      uStack_6c = (uint)uVar4;
      uVar11 = vmv_x_s(auVar21);
      uVar9 = vmv_x_s(auVar19);
      puVar2 = (ushort *)(param_3 + -2);
      pfVar1 = (float *)(param_4 + -0x104);
      puVar3 = (ushort *)(param_3 + -4);
      iVar16 = iVar16 + 1;
      local_70 = (uint)uVar13;
      param_3 = param_3 + 0x90;
      param_4 = param_4 + 0x124;
      fVar17 = (float)(uint)*puVar3 * *pfVar1 *
               (float)(int)((int)(uVar4 >> 0x18) * (int)uVar11 +
                            ((uint)(uVar4 >> 8) & 0xff) * (int)uVar14 +
                            (int)(uVar13 >> 0x18) * (int)uVar8 +
                            ((uint)(uVar13 >> 8) & 0xff) * (int)uVar10 +
                           ((uint)(uVar4 >> 0x10) & 0xff) * (int)uVar9 +
                           (uStack_6c & 0xff) * (int)uVar12 +
                           ((uint)(uVar13 >> 0x10) & 0xff) * (int)uVar7 + uVar6 * (int)uVar15) +
               -((float)(uint)*puVar2 * *pfVar1 * (float)(int)uVar5) + fVar17;
    } while (iVar16 < (int)param_1 >> 8);
    *param_2 = fVar17;
    return;
  }
  *param_2 = 0.0;
  return;
}
```

>Note: Ghidra shows an odd compiler behavior here.  The first iteration of the loop sees vector CSR registers set with `vsetivli_e8m1tama(0xc)`,
>      while subsequent iterations of the loop see `vsetivli_e16m2tama(0xc)`.  This will affect the vle8 instruction at the top of the loop.
>      See [AI survey of gcc RISC-V intrinsics bugs]({{< relref "Llm_surveys/Gcc16_riscv_bugs.md" >}}) for an AI-generated
>      summary of a likely buggy compilation or subtle coding errors.

### Current plugin analytics output

Convert this function into a datatest and run it through the decompiler plugin.  The results include:

```text
Vector Loop (simple):
        control structure is simple
        Loop start address: 0x106306
        Loop length: 0x222
        setvli mode: element size=1, multiplier=1
        vector loads: 14
        vector stores: 1
        integer arithmetic ops: 34
        scalar comparisons: 1
        vector logical ops: 0
        vector integer ops: 0
        vector comparisons: 0
        vector source operands: 14
        vector destination operands: 1
        edges in: 1
        Vector instructions (handled | unhandled | epilog): vle8_v, vsetvli_e8m1tama, vle8_v, vse8_v, vsetvli_e8m1tama, vle8_v, vsetvli_e8m1tama, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vsetvli_e8m1tama, | vsetivli_e16mf2tama, vlse16_v, vlse16_v, vsetivli_e8m1tama, vsetivli_e16mf2tama, vadd_vv, vsrl_vi, vsrl_vi, vsrl_vi, vand_vi, vand_vi, vand_vi, vand_vi, vsrl_vi, vsetivli_e8mf4tama, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vsetvli_e16m2tama, vredsum_vs, vredsum_vs, vredsum_vs, vredsum_vs, vredsum_vs, vredsum_vs, vsetivli_e16mf2tama, vzext_vf2, vsetvli_e16m2tama, vredsum_vs, vredsum_vs, vsetivli_e16mf2tama, vmv_x_s, vmv_x_s, vwmul_vv, vmv_x_s, vmv_x_s, vsetvli_e32m1tama, vredsum_vs, vsetivli_e16m1tama, vmv_x_s, vmv_x_s, vsetivli_e32m1tama, vmv_x_s, vsetivli_e16m2tama, vmv_x_s, vmv_x_s, | ?,
        Loop control variable: u0x00031600:4(0x001064f6:13f) = t3:4(0x00106306:24e) + #0x1:4
        Loop Local-scope Varnodes: a4(0x0010630a:51), a4(0x0010631a:59), a0(0x0010632e:63), a4(0x00106336:67), a7(0x0010633a:69), t1(0x0010633e:6b), a4(0x00106356:76), a4(0x00106362:82), a7(0x00106372:8a), a4(0x00106376:8c), s2(0x00106382:92), t1(0x00106392:9c), s2(0x00106396:9e), u0x00027400:4(0x0010645e:ee), u0x00027400:4(0x0010647a:f8), u0x00027400:4(0x00106496:104), u0x00020c00:4(0x001064a2:109), u0x00027400:4(0x001064b2:112), u0x00099900(0x001064c6:11b), u0x00027400:4(0x001064cc:121), u0x00020c00:4(0x001064d6:127), u0x00015b00(0x001064da:12a), u0x00099900(0x001064e2:130), u0x00027400:4(0x001064e6:133), u0x00020c00:4(0x001064f2:13c), u0x00031600:4(0x001064f6:13f), u0x00027400:4(0x00106500:14e), a2(0x00106506:154), u0x00020c00:4(0x0010650a:155), a3(0x0010650e:158), u0x00027400:4(0x00106512:159), u0x00020c00:4(0x00106516:15b), u0x00020c00:4(0x0010651a:15d), u0x00031900:4(0x0010651e:15f), a2(0x00106306:1c9), a4(0x0010631a:59), a0(0x0010632e:63), a4(0x00106336:67), a4(0x00106356:76), a7(0x0010633a:69), t1(0x0010633e:6b), a4(0x00106362:82), a7(0x00106372:8a), a4(0x00106376:8c), s2(0x00106382:92), s2(0x00106396:9e), t1(0x00106392:9c), s1(0x001062fa:255), sp(0x001062b2:254), u0x00031600:4(0x001064f6:13f),
```

Notes: The loop survey results have limited value

* Manual coding using RISC-V C intrinsics makes this complex loop technically a simple one - there are no interior branches or calls.  It is still a very long simple loop of 546 bytes.
* The number of unhandled instructions makes the count of vector logical ops incorrect.
* The large number of vector multiply and vector sum reduction instructions suggests a striped multiply-add vector operation with a single scalar result
* The loop shifts vector element length between 8, 16, and 32 bits in each iteration, with vector register grouping (`LMUL=2`) used at least once

What can we add to the plugin to support user analysis of such functions? Possibilities include:
* add handlers and trait assignments for common unhandled instructions,  For this loop, that might include:
    * `vsetivli_e8m1tama`
    * `vsetivli_e16mf2tama`
    * `vsetivli_e16m2tama`
    * `vsetivli_e32m1tama`
    * `vsetvli_e32m1tama`
    * `vsetvli_e16m2tama`
    * `vlse16_v` - "Vector strided load"
    * `vredsum_vs` - "Vector Single-Width Integer Reduction Instruction"
    * `vmv_x_s` - "The vmv.x.s instruction copies a single SEW-wide element from index 0 of the source vector register to a destination integer register"
    * `vwmul_vv` - "Widening signed-integer multiply"
    * `vadd_vv` - "Vector Single-Width Integer Add"
    * `vsrl_vi` - "Vector Single-Width Shift Right Instruction" (this may be considered a vector arithmetic op or a vector logical op)
    * `vand_vi` - "Vector Bitwise Logical Instruction"
* add summary lines if `LMUL>1` instructions are present
* count interior vset* instructions
* add an epilog to the survey file showing the 50 most common unhandled instructions encountered during the decompiler's lifetime.
    * Note that this may double-count for functions that see multiple decompilations.