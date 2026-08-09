---
title: Llama's vector dot product optimizations
description: Vector dot products are common in Inference Engine apps.  What optimizations are common?
weight: 190
---

Vector dot products - either alone or as part of matrix multiply and other operations - can be
well worth optimizing in Inference Engine apps.  What kinds of optimizations are we likely to
see, and need to recognize, in the near term?

IE apps tend to use weights of less than 8 bits.  If the calculations are performed on a
CPU rather than a GPU, four bit weight quantization seems to be common.  Let's pick an example where
Q4_1 quantization is chosen for one vector and Q8_1 quantization for the other.  The Q4_1 quantization implies two vector elements per byte, so the 'generic' implementation of this
dot product needs to split the byte into two elements as part of the loop.  quants are
grouped into blocks of 32 elements (16 bytes), with shared `scale` and `min_bias` factors for each block.

```c
void ggml_vec_dot_q4_1_q8_1_generic(int n, float * GGML_RESTRICT s, size_t bs, const void * GGML_RESTRICT vx, size_t bx, const void * GGML_RESTRICT vy, size_t by, int nrc) {
    const int qk = QK8_1;
    const int nb = n / qk;

    assert(n % qk == 0);
    assert(nrc == 1);
    UNUSED(nrc);
    UNUSED(bx);
    UNUSED(by);
    UNUSED(bs);

    const block_q4_1 * GGML_RESTRICT x = vx;
    const block_q8_1 * GGML_RESTRICT y = vy;

    int ib = 0;
    float sumf = 0;

    for (; ib < nb; ++ib) {
        int sumi0 = 0;
        int sumi1 = 0;

        for (int j = 0; j < qk/2; ++j) {
            const int v0 = (x[ib].qs[j] & 0x0F);
            const int v1 = (x[ib].qs[j] >>   4);

            sumi0 += (v0 * y[ib].qs[j]);
            sumi1 += (v1 * y[ib].qs[j + qk/2]);
        }

        int sumi = sumi0 + sumi1;
        sumf += (GGML_CPU_FP16_TO_FP32(x[ib].d)*GGML_CPU_FP16_TO_FP32(y[ib].d))*sumi + GGML_CPU_FP16_TO_FP32(x[ib].m)*GGML_CPU_FP16_TO_FP32(y[ib].s);
    }

    *s = sumf;
}
```

This is the generic source. Compiling with `-O3` and `-march=rv64gcv_zfh_zvfh_zba_zicbop`.
With `-O3` optimization and known block sizes, the compiler chooses to unroll the inner loop
but to *not* attempt vectorization of the loop.

Ghidra decompiles this object file as:

```c
void ggml_vec_dot_q4_1_q8_1_generic
               (long param_1,float *param_2,undefined8 param_3,ushort *param_4,undefined8 param_5,
               ushort *param_6)
{
  int iVar1;
  float fVar2;
  if (0x1f < param_1) {
    fVar2 = 0.0;
    iVar1 = 0;
    do {
      iVar1 = iVar1 + 1;
      fVar2 = fVar2 + (float)(uint)*param_6 * (float)(uint)*param_4 *
                      (float)(int)((int)*(char *)((long)param_6 + 0x23) *
                                   (uint)(*(byte *)((long)param_4 + 0x13) >> 4) +
                                   (int)(char)param_6[0x11] * (uint)(byte)((byte)param_4[9] >> 4) +
                                   (int)*(char *)((long)param_6 + 0x21) *
                                   (uint)(*(byte *)((long)param_4 + 0x11) >> 4) +
                                   (int)(char)param_6[0x10] * (uint)(byte)((byte)param_4[8] >> 4) +
                                   (int)*(char *)((long)param_6 + 0x1f) *
                                   (uint)(*(byte *)((long)param_4 + 0xf) >> 4) +
                                   (int)(char)param_6[0xf] * (uint)(byte)((byte)param_4[7] >> 4) +
                                   (int)*(char *)((long)param_6 + 0x1d) *
                                   (uint)(*(byte *)((long)param_4 + 0xd) >> 4) +
                                   (int)(char)param_6[0xe] * (uint)(byte)((byte)param_4[6] >> 4) +
                                   (int)*(char *)((long)param_6 + 0x1b) *
                                   (uint)(*(byte *)((long)param_4 + 0xb) >> 4) +
                                   (int)(char)param_6[0xd] * (uint)(byte)((byte)param_4[5] >> 4) +
                                   (int)*(char *)((long)param_6 + 0x19) *
                                   (uint)(*(byte *)((long)param_4 + 9) >> 4) +
                                   (int)(char)param_6[0xc] * (uint)(byte)((byte)param_4[4] >> 4) +
                                   (int)*(char *)((long)param_6 + 0x17) *
                                   (uint)(*(byte *)((long)param_4 + 7) >> 4) +
                                   (int)(char)param_6[0xb] * (uint)(byte)((byte)param_4[3] >> 4) +
                                   (int)(char)param_6[10] * (uint)(byte)((byte)param_4[2] >> 4) +
                                   (int)*(char *)((long)param_6 + 0x15) *
                                   (uint)(*(byte *)((long)param_4 + 5) >> 4) +
                                  (int)*(char *)((long)param_6 + 0x13) *
                                  (*(byte *)((long)param_4 + 0x13) & 0xf) +
                                  ((byte)param_4[9] & 0xf) * (int)(char)param_6[9] +
                                  (*(byte *)((long)param_4 + 0x11) & 0xf) *
                                  (int)*(char *)((long)param_6 + 0x11) +
                                  ((byte)param_4[8] & 0xf) * (int)(char)param_6[8] +
                                  (*(byte *)((long)param_4 + 0xf) & 0xf) *
                                  (int)*(char *)((long)param_6 + 0xf) +
                                  ((byte)param_4[7] & 0xf) * (int)(char)param_6[7] +
                                  (*(byte *)((long)param_4 + 0xd) & 0xf) *
                                  (int)*(char *)((long)param_6 + 0xd) +
                                  ((byte)param_4[6] & 0xf) * (int)(char)param_6[6] +
                                  (*(byte *)((long)param_4 + 0xb) & 0xf) *
                                  (int)*(char *)((long)param_6 + 0xb) +
                                  ((byte)param_4[5] & 0xf) * (int)(char)param_6[5] +
                                  (*(byte *)((long)param_4 + 9) & 0xf) *
                                  (int)*(char *)((long)param_6 + 9) +
                                  (int)(char)param_6[4] * ((byte)param_4[4] & 0xf) +
                                  (int)*(char *)((long)param_6 + 7) *
                                  (*(byte *)((long)param_4 + 7) & 0xf) +
                                  (int)(char)param_6[3] * ((byte)param_4[3] & 0xf) +
                                  (int)(char)param_6[2] * ((byte)param_4[2] & 0xf) +
                                  (int)*(char *)((long)param_6 + 5) *
                                  (*(byte *)((long)param_4 + 5) & 0xf)) +
                      (float)(uint)param_4[1] * (float)(uint)param_6[1];
      param_4 = param_4 + 10;
      param_6 = param_6 + 0x12;
    } while (iVar1 < (int)param_1 >> 5);
    *param_2 = fVar2;
    return;
  }
  *param_2 = 0.0;
  return;
}
```

A RISC-V specific version of the source uses C intrinsic functions:

```c
void ggml_vec_dot_q4_1_q8_1(int n, float * GGML_RESTRICT s, size_t bs, const void * GGML_RESTRICT vx, size_t bx, const void * GGML_RESTRICT vy, size_t
 by, int nrc) {
#if defined(__riscv_v)
    const int qk = QK8_1;
    const int nb = n / qk;

    assert(n % qk == 0);
    assert(nrc == 1);
    UNUSED(nrc);
    UNUSED(bx);
    UNUSED(by);
    UNUSED(bs);

    const block_q4_1 * GGML_RESTRICT x = vx;
    const block_q8_1 * GGML_RESTRICT y = vy;

    int ib = 0;
    float sumf = 0;

    size_t vl = qk / 2;

    for (; ib < nb; ++ib) {
        // load elements
        vuint8m1_t tx = __riscv_vle8_v_u8m1(x[ib].qs, vl);

        vint8m1_t y0 = __riscv_vle8_v_i8m1(y[ib].qs, vl);
        vint8m1_t y1 = __riscv_vle8_v_i8m1(y[ib].qs+16, vl);

        // mask and store lower part of x, and then upper part
        vuint8m1_t x_a = __riscv_vand_vx_u8m1(tx, 0x0F, vl);
        vuint8m1_t x_l = __riscv_vsrl_vx_u8m1(tx, 0x04, vl);

        vint8m1_t v0 = __riscv_vreinterpret_v_u8m1_i8m1(x_a);
        vint8m1_t v1 = __riscv_vreinterpret_v_u8m1_i8m1(x_l);

        vint16m2_t vec_mul1 = __riscv_vwmul_vv_i16m2(v0, y0, vl);
        vint16m2_t vec_mul2 = __riscv_vwmacc_vv_i16m2(vec_mul1, v1, y1, vl);

        vint32m1_t vec_zero = __riscv_vmv_v_x_i32m1(0, vl);
        vint32m1_t vs2 = __riscv_vwredsum_vs_i16m2_i32m1(vec_mul2, vec_zero, vl);

        int sumi = __riscv_vmv_x_s_i32m1_i32(vs2);

        sumf += (GGML_CPU_FP16_TO_FP32(x[ib].d)*GGML_CPU_FP16_TO_FP32(y[ib].d))*sumi + GGML_CPU_FP16_TO_FP32(x[ib].m)*GGML_CPU_FP16_TO_FP32(y[ib].s);
    }

    *s = sumf;
#else
    ggml_vec_dot_q4_1_q8_1_generic(n, s, bs, vx, bx, vy, by, nrc);
#endif
}
```

This code relies on the 32 elements always fitting into a 128 bit vector register, absorbing the inner loop into vector instructions.


The RISC-V intrinsics version decompiles as:

```c
void ggml_vec_dot_q4_1_q8_1
               (long param_1,float *param_2,undefined8 param_3,long param_4,undefined8 param_5,
               long param_6)

{
  ushort *puVar1;
  ushort *puVar2;
  ushort *puVar3;
  ushort *puVar4;
  undefined8 uVar5;
  int iVar6;
  float fVar7;
  undefined1 auVar8 [32];
  undefined1 auVar9 [32];
  undefined1 auVar10 [32];
  undefined1 auVar11 [32];
  undefined1 auVar12 [32];

  if (0x1f < param_1) {
    vsetivli_e32m1tama(0x10);
    auVar12 = vmv_v_i(0);
    fVar7 = 0.0;
    param_4 = param_4 + 4;
    param_6 = param_6 + 4;
    iVar6 = 0;
    do {
      vsetivli_e8m1tama(0x10);
      auVar8 = vle8_v(param_4);
      auVar10 = vle8_v(param_6);
      auVar9 = vle8_v(param_6 + 0x10);
      puVar1 = (ushort *)(param_4 + -4);
      puVar2 = (ushort *)(param_6 + -4);
      auVar11 = vand_vi(auVar8,0xf);
      auVar8 = vsrl_vi(auVar8,4);
      auVar10 = vwmul_vv(auVar11,auVar10);
      puVar3 = (ushort *)(param_4 + -2);
      puVar4 = (ushort *)(param_6 + -2);
      auVar8 = vwmacc_vv(auVar8,auVar9,auVar10);
      vsetvli_e16m2tama(0);
      auVar8 = vwredsum_vs(auVar8,auVar12);
      vsetivli_e32m1tama(0);
      iVar6 = iVar6 + 1;
      param_4 = param_4 + 0x14;
      param_6 = param_6 + 0x24;
      uVar5 = vmv_x_s(auVar8);
      fVar7 = fVar7 + (float)(uint)*puVar2 * (float)(uint)*puVar1 * (float)(int)uVar5 +
                      (float)(uint)*puVar3 * (float)(uint)*puVar4;
    } while (iVar6 < (int)param_1 >> 5);
    *param_2 = fVar7;
    return;
  }
  *param_2 = 0.0;
  return;
}
```
