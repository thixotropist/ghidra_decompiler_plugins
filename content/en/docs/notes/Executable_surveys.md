---
title: Survey a large executable for new vector sequences
description: The existing RISC-V vector transforms capture low hanging fruit.  What comes next?
weight: 170
---

The RISC-V plugin recognizes and transforms common vector sequences implementing builtin functions like `memcpy` and `strcmp`.
It generates a lot of survey data too, which can be post-processed into a more readable survey report.  Reports like this can help
identify areas for further study.

## Generating raw survey data

1. Launch Ghidra with the risc-v transform plugin active
2. Clean out any `*.log` or `*.txt` files from `/tmp`.
3. Load the full binary to be surveyed.  We will use `dpdk-l3fwd-O2`, a sample network appliance containing many network adapter
   drivers.
4. Export the full binary as C into `/tmp/dpdk-l3fwd-O2.c`.  This will generate under `/tmp` files like:
    * `dpdk-l3fwd-O2.c`
    * `ghidraRiscvLogger_*.log` - one per spawned decompiler process
    * `riscv_summaries_*.txt` - one per spawned decompiler process
    * `vector_strlen_summaries_*.txt` - one per spawned decompiler process
    * `vector_strcmp_summaries_*.txt` - one per spawned decompiler process
5. Run the survey script with `scripts/process_analytics.py dpdk-l3fwd-O2 full > /tmp/log.md`.
    * optionally convert to HTML with `pandoc  -f markdown -t html -s -V maxwidth=100% /tmp/log.md -o /tmp/log.html`

## Annotated sample output

Annotations are shown in <span style="color:green">green text</span>

# Analysis of dpdk-l3fwd-O2 RISC-V Transform results

## Analysis of C/C++ export file

### Scanning /tmp/dpdk-l3fwd-O2.c

<span style="color:green">
Some functions don't currently decompile in batch mode.  The `multiple descendants` error
is due to a open bug in the decompiler.  The timeouts occur in functions that decompile
to more than 19,000 lines of C.
</span>

* Unable to decompile 'rte_swx_ctl_meter_profile_delete'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'eal_memalloc_mem_event_callback_unregister'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'eal_memalloc_mem_alloc_validator_unregister'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'get_event_config'
		Low-level Error: Free varnode has multiple descendants
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'iavf_get_qos_cap'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'nfp_net_get_eeprom'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'qede_fw_version_get'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'virtio_init_device'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'vhost_vdpa_get_config'
		Low-level Error: Free varnode has multiple descendants
* Cause: Exception while decompiling ram:00783dd8: process: timeout
* Cause: Exception while decompiling ram:007a5242: process: timeout
* Unable to decompile 'virtio_crypto_pkt_tx_burst'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'vhost_vdpa_get_config'
		Low-level Error: Free varnode has multiple descendants

### Summary counts

The export C source code shows successful vector transforms.  The `vector_memcpy` and `vector_memset`
transforms can be formed from either vector series or simple vector loops.  The `vector_strlen` and
`vector_strcmp` are only found in simple vector loops.

| count |transform |
| ---: | :------------ |
| 5977 | vector_memcpy |
| 1666 | vector_memset |
| 190 | vector_strlen |
| 720 | vector_strcmp |

<span style="color:green">
About half of the `vsetvli` and `vsetivli` instructions have been absorbed during transforms.  The following reports
instructions that aren't yet safely absorbed.
</span>

>Note: Also found 10592 other vsetvli or vsetivli instructions

## Analysis of transform logger file /tmp/ghidraRiscvLogger.log

This plugin generates warnings when it can no longer continue with a transform attempt.

### Warning summary counts
| count | text |
| ---: | :------------- |
| 2583 | Unable to fully analyze potential complex vector loop stanza |
| 2053 | Failed to extract Vector store pExternal varnode |
| 1486 | Unable to complete transform due to reference to loop-local Varnode |
| 1404 | Failed to extract Vector load pExternal varnode |
| 1272 | Unrecognized number of vector pcode arguments |
| 1012 | Unable to complete transform due to one or more references to a loop-local Varnode |
| 88 | Vector vset found with no output register |
| 10 | Failed to collect source register from a vector load operation |
| 4 | Unrecognized number of scalar pcode arguments |

## Analysis of loop and series summary file

**Simple loop signatures**

Simple loops consist of a single Ghidra block with no internal jumps or calls other than
the conditional branch returning to the start of the block.  Builtins like `memcpy` and
`strcmp` generally result in simple loops.

Recognized (aka 'handled') vector instruction sequences are found in simple loop bodies
The most common 50 are:

| count | handled instructions |
| ---: | :-------- |
| 3261 | vsetvli_e8m1tama, vle8_v, vse8_v |
| 875 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmsne_vv, vmseq_vi, vmor_mm, vfirst_m |
| 252 | vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m |
| 12 | vle8_v, vse16_v |
| 6 | vsetvli_e8mf2tama, vse16_v |
| 6 | vle32_v, vse32_v |
| 6 | vse16_v |
| 6 | vle64_v, vse64_v |
| 5 | vsetvli_e8mf4tama |
| 5 | vle8_v |
| 4 | vsetvli_e8mf4tama, vle32_v, vsetvli_e8m1tama, vse32_v |
| 4 | vle16_v, vse32_v |
| 4 | vmseq_vi, vfirst_m |
| 3 | vsetvli_e8mf4tama, vse32_v |
| 2 | vle64_v, vse16_v |
| 2 | vsetvli_e8mf8tama, vle64_v, vsetvli_e8m1tama, vse64_v |
| 2 | vsetvli_e8mf2tama |
| 2 | vsetvli_e8mf2tama, vle8_v, vmseq_vi |
| 1 | vsetvli_e8m1tama |
| 1 | vse32_v |
| 1 | vsetvli_e8m1tama, vle8_v, vle8_v, vse8_v |
| 1 | vmseq_vi |
| 1 | vle32_v, vle32_v, vse32_v |
| 1 | vle32_v, vse16_v |
| 1 | vle64_v |
| 1 | vle8_v, vse32_v |
| 1 | vse16_v, vse16_v, vse16_v, vse16_v |
| 1 | vle64_v, vle32_v, vse64_v |
| 1 | vsetvli_e8m1tama, vle8_v, vle8_v, vse8_v, vle8_v, vse8_v |
| 1 | vle32_v, vle32_v, vmsne_vv |
| 1 | vsetvli_e8m1tama, vse8_v, vsetvli_e8m1tama |
| 1 | vsetvli_e8m1tama, vle8_v, vse8_v, vle8_v, vse8_v |
| 1 | vle32_v |

**Complex loop signatures**

Recognized (aka 'handled') vector instruction saequences are found in complex loop bodies
The most common 50 are:

| count | handled instructions |
| -: | :-------- |
| 226 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmseq_vi, vmsne_vv |
| 59 | vse16_v |
| 54 | vle16_v |
| 38 | vsetvli_e8m1tama, vle8_v, vse8_v |
| 19 | vsetvli_e8m1tama |
| 14 | vse64_v |
| 13 | vse32_v |
| 12 | vle32_v |
| 7 | vsetvli_e8mf2tama |
| 7 | vse16_v, vse64_v |
| 6 | vsetvli_e8mf4tama |
| 6 | vsetvli_e8mf8tama, vse8_v |
| 6 | vse8_v, vse32_v |
| 5 | vsetvli_e8mf8tama, vse32_v, vse8_v |
| 5 | vle32_v, vsetvli_e8mf8tama, vse8_v |
| 5 | vsetvli_e8mf2tama, vsetvli_e8mf2tama |
| 5 | vs1r_v |
| 5 | vse32_v, vse64_v |
| 5 | vse16_v, vse32_v |
| 4 | vse8_v |
| 4 | vle32_v, vmseq_vi |
| 4 | vsetvli_e8mf4tama, vle32_v, vle32_v, vsetvli_e8m1tama |
| 4 | vsetvli_e8mf4tama, vle32_v, vsetvli_e8m1tama |
| 4 | vsetvli_e8mf8tama, vse8_v, vse32_v |
| 4 | vsetvli_e8mf2tama, vse16_v |
| 4 | vsetvli_e8mf4tama, vse8_v |
| 3 | vse16_v, vse16_v |
| 3 | vle16_v, vse32_v |
| 3 | vsetvli_e8mf4tama, vsetvli_e8mf4tama |
| 3 | vle8_v |
| 3 | vle32_v, vse16_v |
| 3 | vle64_v, vse32_v |
| 3 | vse32_v, vse64_v, vse32_v, vse32_v |
| 2 | vsetvli_e8mf8tama |
| 2 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v |
| 2 | vle32_v, vse16_v, vse16_v |
| 2 | vse64_v, vse32_v |
| 2 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmsne_vv, vmseq_vi, vmor_mm, vfirst_m |
| 2 | vle64_v, vle64_v, vse32_v |
| 2 | vse64_v, vsetvli_e8mf8tama, vse8_v |
| 2 | vle16_v, vsetvli_e8mf8tama, vse8_v |
| 2 | vsetvli_e8mf4tama, vle8_v |
| 2 | vs1r_v, vs1r_v, vs1r_v |
| 2 | vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi |
| 2 | vsetvli_e8mf4tama, vle16_v |
| 2 | vse32_v, vse32_v |
| 2 | vl1re16_v, vse16_v, vse16_v |
| 2 | vse32_v, vse16_v, vse16_v, vse16_v |
| 2 | vle64_v, vse16_v |
| 2 | vsetvli_e8mf8tama, vse16_v, vse8_v |

**Unhandled loop instructions**

Handled vector instructions each have a lambda expression providing for their basic semantics.
Unhandled instructions have no such lambda defined, and can not be used in a transform match.

The most common 50 are:

| count | unhandled instructions |
| -: | :-------- |
| 192 | vsetvli_e32m1tama |
| 179 | vid_v |
| 158 | vmv_v_i |
| 155 | vnsrl_wi |
| 146 | vmv_x_s |
| 139 | vsetvli_e16mf4tama |
| 119 | vmul_vx |
| 113 | vsetvli_e32mf2tama |
| 106 | vsetvli_e64m1tama |
| 95 | vsetivli_e32mf2tama |
| 88 | vadd_vv |
| 87 | vsrl_vi |
| 78 | vmv_s_x |
| 76 | vadd_vx |
| 72 | vmv_v_x |
| 71 | vsetivli_e32m1tama |
| 64 | vor_vv |
| 64 | vcompress_vm |
| 62 | vand_vx |
| 60 | vsetivli_e16mf4tama |
| 60 | vsetvli_e16mf2tama |
| 54 | vsll_vi |
| 54 | vsetivli_e16mf2tama |
| 54 | vwredsumu_vs |
| 53 | vrsub_vi |
| 53 | vzext_vf2 |
| 47 | vand_vi |
| 47 | vsetvli_e16m1tama |
| 46 | vsetivli_e8m1tama |
| 43 | vsetivli_e8mf8tama |
| 42 | vadd_vi |
| 41 | vlm8_v |
| 39 | vslidedown_vi |
| 38 | vmv1r_v |
| 38 | vand_vv |
| 34 | vsrl_vv |
| 33 | vslideup_vi |
| 32 | vrgather_vv |
| 29 | vsetivli_e64m1tama |
| 28 | vmerge_vim |
| 26 | vzext_vf4 |
| 22 | vsetvli_e64m8tama |
| 19 | vrgatherei16_vv |
| 18 | vsetvli_e32m4tama |
| 16 | vxor_vv |
| 16 | vsetivli_e8mf4tama |
| 15 | vsub_vv |
| 14 | vmsne_vi |
| 13 | vmerge_vvm |
| 12 | vsetvli_e64m2tama |
