---
title: Control and Status Registers
weight: 70
description: How do we want to handle vector control and status registers?
---

>Summary: Ghidra can treat control and status registers as registers or as memory locations, or even
>         as function calls.  What are the tradeoffs?

The `vector_strlen` instruction pattern usually needs to load the `vl` csr.  This is one of two similar
patterns found in `whisper_cpp::main`:

```as
0221ea   c.li      a5,0x0

LAB_ram_000221f6:        ram:000221ee(j), ram:0002220c(j)
0221f6   c.add     a0,a5
0221f8   vsetvli   a5,zero,e8,m1,ta,ma
0221fc   vle8ff.v  v1,(a0)
022200   vmseq.vi  v1,v1,0x0
022204   csrr      a5,vl
022208   vfirst.m  a4,v1
02220c   blt       a4,zero,LAB_ram_000221f6
```

The `csrr` instruction sets register `a5` to the number of bytes loaded in the previous
`vle8ff.v` instruction.  That number is not known until runtime, as the `vle8ff.v` will ask for
as many bytes as may fit in a vector register, but that load may trigger a page fault.

Ghidra's decompiler generates Pcode from these instructions as:

```text
0x000221f6:34bb:    a5(0x000221f6:34bb) = u0x1000263a(0x000221ee:1b658) ? u0x10002642(0x0002220c:1b659)
0x000221f6:2bdc:    a0(0x000221f6:2bdc) = u0x100025aa(0x000221ee:1b646) ? a0(0x000221f6:b87)
0x000221f6:b87:     a0(0x000221f6:b87) = a0(0x000221f6:2bdc) + a5(0x000221f6:34bb)(*#0x1)
0x000221f8:b88:     vsetvli_e8m1tama(#0x0)
0x000221fc:b8a:     v1(0x000221fc:b8a) = vle8ff_v(a0(0x000221f6:b87))
0x00022200:b8c:     v1(0x00022200:b8c) = vmseq_vi(v1(0x000221fc:b8a),#0x0)
0x00022208:b8e:     a4(0x00022208:b8e) = vfirst_m(v1(0x00022200:b8c))
0x0002220c:b8f:     u0x00002080:1(0x0002220c:b8f) = a4(0x00022208:b8e) < #0x0
0x0002220c:1b659:   u0x10002642(0x0002220c:1b659) = c0x0c20(0x000221e4:7bbb)
0x0002220c:b90:     goto Block_245:0x000221f6 if (u0x00002080:1(0x0002220c:b8f) != 0) else Block_246:0x00022210
```

The `vl` CSR is named `csreg:0xc20` within the `RV64.pspec` file.  Its value is not known until runtime, and even
then it is not deterministic if the vector load crosses a virtual memory page boundary.  Ghidra's decompiler
tries hard to track its heritage and dependencies anyway, guessing that it was most recently set in a previous
subroutine call.  The decompiler inserts 437 Phi-node or MULTIEQUAL pcode ops in this main routine in that attempt
to track the histories of the two `csrr reg,vl` instructions present in `main`.

The whisper.cpp RVA23 executable shows 998 instances of the csrr instruction, loading to a register either the `vl` or `vlenb` CSR (aka `csreg:0xc22`).
The `vlenb` register gives the current hart's vector length in bytes, which means it is set in hardware depending
on the execution core selected at runtime.

The csrr instruction is defined in `riscv.csr.sinc` as:

```text
:csrr rdDst,csr is csr & rdDst & op0001=0x3 & op0204=0x4 & op0506=0x3 & funct3=0x2 & op1519=0 & op0711
{
        rdDst = csr:$(XLEN);
}
```

Checking the dpdk-pipeline exemplar shows 4259 instances of the csrr instruction, mostly loading the `vl`, `vlenb`,
or `time` CSR.