---
title: Whisper.cpp voice to text inference engine
description: The Whisper application inference engine uses the GGML library to do tensor math.
weight: 20
---

## Source code analysis

## Ghidra and build summary

* 2.0 MB binary file size, with debugging and symbols
* 275K instructions
* 1.9K functions
* compiled with GCC 15.0.1
* compiler options include `-O3`

## Script Analysis of whisper_cpp_rva23 RISC-V Transform results

## Summary counts
The export C source code shows successful vector transforms.  The `vector_memcpy` and
`vector_memset` transforms can be formed from either vector series or simple vector loops.
The `vector_strlen` and `vector_strcmp` are only found in simple vector loops.

| count |transform |
| ---: | :------------ |
| 1166 | vector_memcpy |
| 414 | vector_memset |
| 90 | vector_strlen |
| 15 | vector_strcmp |

>Note: Also found 4646 other vsetvli or vsetivli instructions

## Analysis of transform logger file /tmp/ghidraRiscvLogger.log

This plugin generates warnings when it can no longer continue with a transform attempt.

### Warning summary counts

| count | text |
| ---: | :------------- |
| 20940 | Failed to extract Vector load pExternal varnode |
| 16509 | Failed to extract Vector store pExternal varnode |
| 4476 | Unable to fully analyze potential complex vector loop stanza |
| 758 | Vector vset found with no output register |
| 639 | Unrecognized number of vector pcode arguments |
| 230 | Unable to complete transform due to reference to loop-local Varnode |
| 152 | Unable to complete transform due to one or more references to a loop-local Varnode |

## Analysis of loop and series summary file


**Simple loop signatures**

Simple loops consist of a single Ghidra block with no internal jumps or calls other than
the conditional branch returning to the start of the block.  Builtins like `memcpy` and
`strcmp` generally result in simple loops.

Recognized (aka 'handled') vector instruction sequences are found in simple loop bodies:
The most common 50 are:

| count | handled instructions |
| ---: | :-------- |
| 936 | vsetvli_e8m1tama, vle8_v, vse8_v |
| 99 | vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m |
| 44 | vle32_v |
| 40 | vle32_v, vse32_v |
| 24 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmsne_vv, vmseq_vi, vmor_mm, vfirst_m |
| 23 | vle32_v, vle32_v, vse32_v |
| 19 | vsetvli_e8mf4tama, vse32_v |
| 14 | vsetvli_e8mf4tama, vle32_v, vse32_v |
| 11 | vse32_v |
| 9 | vle32_v, vle32_v |
| 8 | vsetvli_e8mf4tama |
| 8 | vle16_v, vse16_v |
| 6 | vle8_v, vse32_v |
| 6 | vsetvli_e8mf2tama, vse16_v |
| 5 | vle16_v, vse32_v |
| 5 | vle64_v, vse64_v |
| 4 | vle64_v, vle64_v, vle64_v, vse64_v, vse64_v, vse64_v |
| 4 | vle32_v, vse16_v |
| 4 | vle16_v, vle16_v |
| 4 | vsetvli_e8mf4tama, vle32_v, vsetvli_e8m1tama, vse32_v |
| 3 | vsetvli_e8mf8tama, vse8_v |
| 3 | vle8_v |
| 3 | vle16_v |
| 3 | vle16_v, vle16_v, vse16_v |
| 3 | vse16_v |
| 2 | vle8_v, vse16_v |
| 2 | vle8_v, vle8_v, vle8_v, vle8_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v |
| 2 | vsetvli_e8mf4tama, vle8_v, vsetvli_e8mf4tama, vse32_v, vsetvli_e8mf4tama, vse32_v |
| 2 | vsetvli_e8mf2tama, vle16_v |
| 2 | vle8_v, vle8_v, vle8_v, vsetvli_e8mf4tama, vse8_v, vle8_v, vse8_v, vse8_v |
| 2 | vle16_v, vle32_v, vse16_v |
| 2 | vsetvli_e8mf8tama, vle64_v, vse64_v |
| 2 | vsetvli_e8mf2tama, vle16_v, vse16_v |
| 2 | vsetvli_e8mf2tama, vle8_v, vle8_v, vle8_v |
| 2 | vle8_v, vsetvli_e8mf2tama, vle8_v, vle8_v, vle8_v, vse8_v, vsetvli_e8mf2tama, vsetvli_e8mf2tama |
| 2 | vl1re32_v, vsetvli_e8mf4tama, vse32_v |
| 2 | vle64_v |
| 2 | vsetvli_e8mf8tama, vle64_v, vsetvli_e8m1tama, vse64_v |
| 2 | vsetvli_e8mf4tama, vle32_v, vle32_v, vse32_v, vse32_v |
| 2 | vle32_v, vse64_v |
| 2 | vsetvli_e8mf4tama, vle8_v, vle8_v, vle8_v, vsetvli_e8mf4tama |
| 1 | vle64_v, vse16_v |
| 1 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vse8_v |
| 1 | vsetvli_e8mf4tama, vle8_v, vle8_v, vse8_v, vle8_v, vle8_v, vle8_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v |
| 1 | vsetvli_e8mf4tama, vle32_v |
| 1 | vsetvli_e8mf4tama, vsetvli_e8mf4tama, vmseq_vi, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vmseq_vi, vsetvli_e8mf4tama, vmseq_vi, vsetvli_e8mf4tama, vmseq_vi, vsetvli_e8mf4tama, vmseq_vi, vsetvli_e8mf4tama, vmseq_vi, vsetvli_e8mf4tama, vmseq_vi, vsetvli_e8mf4tama, vmseq_vi, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v |
| 1 | vle16_v, vle32_v, vse32_v |
| 1 | vsetvli_e8mf4tama, vle8_v, vse8_v, vle8_v, vle8_v, vle8_v, vle8_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v |
| 1 | vse64_v, vse64_v |
| 1 | vle32_v, vle32_v, vse32_v, vse32_v |

**Complex loop signatures**

Complex loops consist of multiple Ghidra blocks with at least one internal jump or call other than
the conditional branch returning to the start of the block.  Builtins like `strncmp`
generally result in complex loops.

Recognized (aka 'handled') vector instruction sequences  are found in complex loop bodies:

The most common 50 are:

| count | handled instructions |
| -: | :-------- |
| 29 | vsetvli_e8mf4tama |
| 8 | vle32_v, vsetvli_e8mf4tama, vse8_v, vle32_v, vsetvli_e8mf4tama, vse8_v, vle32_v, vsetvli_e8mf4tama, vse8_v, vle32_v, vsetvli_e8mf4tama, vse8_v, vle32_v, vsetvli_e8mf4tama, vse8_v, vle32_v, vsetvli_e8mf4tama, vse8_v, vle32_v, vsetvli_e8mf4tama, vse8_v, vle32_v, vsetvli_e8mf4tama, vse8_v |
| 7 | vsetvli_e8mf8tama, vsetvli_e8mf8tama |
| 4 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v |
| 4 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse8_v, vse8_v, vse8_v, vse8_v |
| 4 | vsetvli_e8m1tama |
| 3 | vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse8_v, vse8_v, vse8_v, vse8_v |
| 3 | vsetvli_e8mf4tama, vle8_v, vse8_v |
| 3 | vle8_v, vsetvli_e8mf4tama, vse8_v |
| 3 | vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v |
| 3 | vle8_v, vsetvli_e8mf2tama, vse8_v |
| 3 | vle8_v, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama |
| 3 | vs1r_v |
| 3 | vl1re32_v |
| 3 | vsetvli_e8m1tama, vse8_v |
| 2 | vle32_v, vse32_v, vle32_v, vse32_v, vle32_v, vle32_v, vse32_v |
| 2 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v |
| 2 | vle32_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama |
| 2 | vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle32_v, vle32_v, vle8_v, vle8_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v |
| 2 | vsetvli_e8mf4tama, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v |
| 2 | vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v |
| 2 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v |
| 2 | vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v |
| 2 | vs1r_v, vse8_v |
| 2 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse8_v, vse8_v, vse8_v, vse8_v, vse8_v, vse8_v, vse8_v, vse8_v |
| 2 | vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf4tama, vle8_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse8_v, vse8_v, vse8_v |
| 2 | vle8_v, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama |
| 2 | vle8_v, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama |
| 2 | vle32_v |
| 2 | vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vsetvli_e8mf4tama, vle8_v, vsetvli_e8mf4tama, vle8_v, vsetvli_e8mf4tama, vle8_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama |
| 2 | vle8_v, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama |
| 2 | vsetvli_e8mf8tama |
| 2 | vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi |
| 2 | vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v |
| 2 | vle32_v, vle32_v, vse32_v, vle32_v, vle32_v, vse32_v, vle32_v, vle32_v, vse32_v, vle32_v, vle32_v, vse32_v, vle32_v, vle32_v, vse32_v, vle32_v, vle32_v, vse32_v |
| 1 | vle32_v, vle32_v, vle32_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vse8_v, vse8_v |
| 1 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vse8_v |
| 1 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vse8_v, vse8_v |
| 1 | vle32_v, vse16_v |
| 1 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf4tama, vle32_v, vsetvli_e8mf4tama, vle32_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vle8_v, vse8_v, vsetvli_e8mf4tama, vse8_v, vse8_v, vse8_v, vse8_v |
| 1 | vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse32_v, vsetvli_e8mf4tama, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v |
| 1 | vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vle8_v, vle8_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse32_v, vsetvli_e8mf4tama, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v, vse32_v |
| 1 | vse32_v, vse32_v, vse32_v |
| 1 | vle8_v, vle8_v, vle8_v, vle32_v, vle8_v, vle8_v, vle32_v, vle8_v, vle8_v, vle32_v, vle8_v, vle32_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vle8_v, vse8_v, vse8_v, vse8_v, vse8_v, vse8_v |
| 1 | vle8_v, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama |
| 1 | vle8_v, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama, vsetvli_e8mf8tama |
| 1 | vle32_v, vle32_v, vsetvli_e8mf4tama |
| 1 | vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse8_v, vse8_v |
| 1 | vle32_v, vle32_v, vle32_v, vse32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vle32_v, vse8_v, vse8_v, vsetvli_e8mf4tama, vle32_v, vse32_v, vse8_v, vsetvli_e8mf4tama, vse8_v, vse32_v, vsetvli_e8mf4tama, vle32_v, vse8_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vle32_v, vle32_v, vle32_v, vle32_v, vse32_v, vse32_v, vle32_v, vle32_v, vse32_v, vle32_v, vse32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vse32_v, vse32_v, vse32_v, vsetvli_e8mf4tama, vse8_v |
| 1 | vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vle32_v, vsetvli_e8mf4tama, vle32_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vsetvli_e8mf4tama, vse8_v, vse8_v, vse8_v, vse8_v, vse8_v |

**Unhandled loop instructions**

Handled vector instructions each have a lambda expression providing for their basic semantics.
Unhandled instructions have no such lambda defined, and can not be used in a transform match.

The most common 50 are:

| count | unhandled instructions |
| -: | :-------- |
| 700 | vsetvli_e32m1tama |
| 699 | vncvt_xxw |
| 627 | vfmul_vv |
| 476 | vadd_vv |
| 458 | vsetvli_e16mf2tama |
| 449 | vfmadd_vv |
| 400 | vand_vv |
| 397 | vmv1r_v |
| 307 | vfcvt_fxv |
| 282 | vand_vi |
| 234 | vsext_vf2 |
| 219 | vzext_vf4 |
| 201 | vluxei64_v |
| 198 | vadd_vi |
| 196 | vmin_vv |
| 195 | vsetvli_e32mf2tama |
| 193 | vmax_vv |
| 185 | vfmacc_vv |
| 182 | vfadd_vv |
| 178 | vmv_v_x |
| 171 | vsrl_vi |
| 154 | vor_vv |
| 150 | vsll_vi |
| 136 | vmsne_vi |
| 132 | vfwcvt_f_x_v |
| 130 | vfmv_vf |
| 113 | vfsub_vv |
| 106 | vsetvli_e64m1tama |
| 101 | vfmv_fs |
| 99 | vslidedown_vi |
| 93 | vsetvli_e32mf2tamu |
| 92 | vmadd_vv |
| 92 | vwmul_vv |
| 91 | vmv_x_s |
| 88 | vcompress_vm |
| 79 | vmul_vv |
| 78 | vsetivli_e32m1tama |
| 77 | vslideup_vi |
| 72 | vsetvli_e16mf4tama |
| 69 | vsext_vf4 |
| 65 | vmv_v_i |
| 65 | vfsgnjn_vv |
| 64 | vwmulsu_vv |
| 64 | vneg_v |
| 60 | vmulhu_vv |
| 58 | vmerge_vvm |
| 52 | vnsrl_wi |
| 52 | vsetvli_e32mf2tuma |
| 48 | vsll_vv |
| 47 | vfredusum_vs |
