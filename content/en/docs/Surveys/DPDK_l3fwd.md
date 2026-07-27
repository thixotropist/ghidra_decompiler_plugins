---
title: Dataplane development kit packet processing
description: The DPDK L3-FWD app survey examines many network drivers
weight: 10
---

This [app](https://github.com/DPDK/dpdk.git) collects user-space drivers and routing logic
from many network adapter instances.  It likely presents a good exemplar for device drivers
in general, with lots of data transformations and rather little math.

* Source code commit `0c0f70f98dcf5b860b2e422ad20f40cc9f1d3705` pulled 1 June 2026

## Source code analysis

The distribution includes several optional alternate function definitions which *may* be selected
for a RISC-V RVA23 build.  These are *not* enabled in the current builds, which focus instead
on compiler vectorizations of basic C or C++ code.  They are worth noting here because the
developers have gone to the effort to manually vectorize code they expect to form
an operational bottleneck.  That manual optimization appears to focus on Forwarding Information
Base and Access Control List tree search optimizations where the correct handler must
be determined based on IP address.  The resulting code enables multiple packets to be processed
in parallel.

## With `-O2` optimization

### Ghidra and build summary

* 50 MB binary file size, with debugging and symbols
* 2.6M instructions
* 24K functions
* compiled with GCC 15.2
* compiler options are `-std=c11 -O2 -march=rv64_gcv`

### Script Analysis of dpdk-l3fwd-O2 RISC-V Transform results

Exporting the entire binary `dpdk-l3fwd-O2` as C then running
the decompiler analysis script provides some insight into
how vector instructions are used and what further effort might be
worthwhile.

* There are a lot of vector instructions present in an application that
  presents few obvious opportunities for hotspot vector optimizations.
* About 10 functions fail to decompile because of a Ghidra error.
  A PR fix was submitted but is not yet merged.
* Single functions with nearly 20K lines of code trigger a timeout
  during batch export.  They complete normally when decompiling singly.
* Transforms recognizing single-block libc standard functions like
  `memcpy` and `strlen` are well worthwhile.
* Resolving the warnings like `Failed to extract Vector ... pExternal varnode`
  should improve the number of matches - unless these are due to non libc code fragments.
* There appear to be about 220 instances of `strncmp`.  Transforming these involves absorption of
  multiple Ghidra blocks into a single function call, and may not be easy.
* There are no observed instances of LMUL > 1, suggesting that we don't have to worry about vector
  register grouping in the short term.
* There are fewer instances of compiler-driven loop auto-vectorization with `-O2` optimization

#### Analysis of C/C++ export file

##### Scanning /tmp/dpdk-l3fwd-O2.c

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

##### Summary counts

The export C source code shows successful vector transforms.  The `vector_memcpy` and vector_memset`
transforms can be formed from either vector series or simple vector loops.  The `vector_strlen` and
`vector_strcmp` are only found in simple vector loops.

| count |transform |
| ---: | :------------ |
| 5977 | vector_memcpy |
| 1666 | vector_memset |
| 190 | vector_strlen |
| 720 | vector_strcmp |

>Note: Also found 10592 other vsetvli or vsetivli instructions

#### Analysis of transform logger file /tmp/ghidraRiscvLogger.log

This plugin generates warnings when it can no longer continue with a transform attempt.

##### Warning summary counts

| count | text |
| ---: | :------------- |
| 2583 | Unable to fully analyze potential complex vector loop stanza |
| 2053 | Failed to extract Vector store pExternal varnode |
| 1488 | Unable to complete transform due to reference to loop-local Varnode |
| 1404 | Failed to extract Vector load pExternal varnode |
| 1272 | Unrecognized number of vector pcode arguments |
| 1014 | Unable to complete transform due to one or more references to a loop-local Varnode |
| 88 | Vector vset found with no output register |
| 10 | Failed to collect source register from a vector load operation |
| 4 | Unrecognized number of scalar pcode arguments |

#### Analysis of loop and series summary file

**Simple loop signatures**

Simple loops consist of a single Ghidra block with no internal jumps or calls other than
the conditional branch returning to the start of the block.  Builtins like `memcpy` and
`strcmp` generally result in simple loops.

Recognized (aka 'handled') vector instruction signatures found in simple loop bodies:
The most common 50 are:

| count | handled instructions |
| ---: | :-------- |
| 3483 | vsetvli_e8m1tama, vle8_v, vse8_v |
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

Complex loops consist of multiple Ghidra blocks with at least one internal jump or call other than
the conditional branch returning to the start of the block.  Builtins like `strncmp`
generally result in complex loops.

Recognized (aka 'handled') vector instruction signatures are found in complex loop bodies.

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

## With `-O3` optimization

Repeat the analysis with a *roughly similar* binary compiled with `-O3` optimization.

### Ghidra and build summary

* 52 MB binary file size, with debugging and symbols
* 3.0M instructions
* 23K functions
* compiled with GCC 15.2
* compiler options are `-std=c11 -O3 -march=rv64_gcv`

### Script Analysis of dpdk-l3fwd-O2 RISC-V Transform results

#### Analysis of C/C++ export file

##### Scanning /tmp/dpdk-l3fwd-O3.c

* Unable to decompile 'rte_swx_ctl_meter_profile_delete'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'rte_port_ring_writer_tx_bulk'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'eal_memalloc_mem_event_callback_unregister'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'eal_memalloc_mem_alloc_validator_unregister'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'get_event_config'
		Low-level Error: Free varnode has multiple descendants
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'dpaa2_print_parse_result'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'iavf_get_qos_cap'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'nfp_sync_handle_free'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'nfp_sync_handle_count_get'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'nfp_net_get_eeprom'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'qede_fw_version_get'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'virtio_init_device'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'vhost_vdpa_get_config'
		Low-level Error: Free varnode has multiple descendants
* Cause: Exception while decompiling ram:0088aece: process: timeout
* Unable to decompile 'virtio_crypto_pkt_tx_burst'
		Low-level Error: Free varnode has multiple descendants
* Unable to decompile 'vhost_vdpa_get_config'
		Low-level Error: Free varnode has multiple descendants

##### Summary counts
The export C source code shows successful vector transforms.  The `vector_memcpy` and
`vector_memset` transforms can be formed from either vector series or simple vector loops.
The `vector_strlen` and `vector_strcmp` are only found in simple vector loops.

| count |transform |
| ---: | :------------ |
| 7541 | vector_memcpy |
| 1918 | vector_memset |
| 229 | vector_strlen |
| 845 | vector_strcmp |

>Note: Also found 19019 other vsetvli or vsetivli instructions

#### Analysis of transform logger file /tmp/ghidraRiscvLogger.log

This plugin generates warnings when it can no longer continue with a transform attempt.

##### Warning summary counts
| count | text |
| ---: | :------------- |
| 6195 | Unable to fully analyze potential complex vector loop stanza |
| 5362 | Failed to extract Vector load pExternal varnode |
| 4632 | Failed to extract Vector store pExternal varnode |
| 2968 | Unrecognized number of vector pcode arguments |
| 2756 | Vector vset found with no output register |
| 1638 | Unable to complete transform due to reference to loop-local Varnode |
| 1149 | Unable to complete transform due to one or more references to a loop-local Varnode |
| 62 | Unrecognized number of scalar pcode arguments |

#### Analysis of loop and series summary file

**Simple loop signatures**

Simple loops consist of a single Ghidra block with no internal jumps or calls other than
the conditional branch returning to the start of the block.  Builtins like `memcpy` and
`strcmp` generally result in simple loops.

Recognized (aka 'handled') vector instruction sequences are found in simple loop bodies:
The most common 50 are:

| count | handled instructions |
| ---: | :-------- |
| 3536 | vsetvli_e8m1tama, vle8_v, vse8_v |
| 1000 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmsne_vv, vmseq_vi, vmor_mm, vfirst_m |
| 356 | vsetvli_e8mf8tama, vle64_v, vse64_v |
| 293 | vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m |
| 50 | vle64_v |
| 40 | vsetvli_e8mf4tama, vle32_v, vse32_v |
| 14 | vse64_v |
| 14 | vle8_v |
| 13 | vse32_v |
| 13 | vsetvli_e8mf4tama, vse32_v |
| 12 | vle8_v, vse16_v |
| 11 | vsetvli_e8mf2tama, vse16_v |
| 10 | vle64_v, vse64_v |
| 9 | vle16_v |
| 9 | vle32_v, vse32_v |
| 8 | vle64_v, vle64_v, vse64_v |
| 8 | vle32_v |
| 8 | vse16_v |
| 7 | vle64_v, vsetvli_e8mf8tama |
| 7 | vmseq_vi |
| 6 | vsetvli_e8mf4tama |
| 6 | vsetvli_e8mf4tama, vle32_v, vsetvli_e8m1tama, vse32_v |
| 4 | vle32_v, vse16_v, vse64_v, vse64_v |
| 4 | vle16_v, vse32_v |
| 4 | vsetvli_e8mf8tama, vsetvli_e8m1tama, vse64_v |
| 4 | vsetvli_e8mf2tama, vle16_v, vse16_v |
| 4 | vsetvli_e8mf4tama, vsetvli_e8mf4tama, vse8_v |
| 4 | vmseq_vi, vfirst_m |
| 3 | vsetvli_e8mf2tama |
| 3 | vle8_v, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama |
| 3 | vle8_v, vse32_v |
| 3 | vsetvli_e8mf4tama, vse8_v |
| 3 | vsetvli_e8mf8tama, vle64_v, vsetvli_e8m1tama, vse64_v |
| 2 | vsetvli_e8mf2tama, vle8_v, vmseq_vi |
| 2 | vle64_v, vse32_v |
| 2 | vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama, vsetvli_e8mf4tama |
| 2 | vmseq_vi, vse32_v |
| 2 | vle64_v, vse16_v |
| 2 | vsetvli_e8mf4tama, vsetvli_e8mf4tama |
| 2 | vle16_v, vle64_v, vse64_v |
| 2 | vle64_v, vle64_v |
| 2 | vsetvli_e8mf8tama, vsetvli_e8mf8tama |
| 2 | vsetvli_e8mf8tama, vle32_v, vse64_v |
| 2 | vsetvli_e8mf8tama, vle32_v |
| 2 | vsetvli_e8mf8tama, vsetvli_e8m1tama |
| 2 | vle32_v, vl1re32_v, vse32_v |
| 1 | vle32_v, vsetvli_e8mf4tama |
| 1 | vmseq_vi, vmseq_vi |
| 1 | vle32_v, vle32_v, vmsne_vv |
| 1 | vle32_v, vle32_v, vse32_v, vle32_v, vse32_v |

**Complex loop signatures**

Complex loops consist of multiple Ghidra blocks with at least one internal jump or call other than
the conditional branch returning to the start of the block.  Builtins like `strncmp`
generally result in complex loops.

Recognized (aka 'handled') vector instruction sequences  are found in complex loop bodies:

The most common 50 are:

| count | handled instructions |
| -: | :-------- |
| 259 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmseq_vi, vmsne_vv |
| 92 | vse16_v |
| 70 | vle16_v |
| 68 | vsetvli_e8mf4tama |
| 47 | vsetvli_e8m1tama, vle8_v, vse8_v |
| 37 | vsetvli_e8m1tama |
| 24 | vs1r_v |
| 22 | vsetvli_e8mf8tama, vse8_v |
| 17 | vle64_v, vse64_v, vse32_v |
| 13 | vle32_v |
| 13 | vse32_v |
| 12 | vse64_v |
| 12 | vsetvli_e8mf8tama |
| 12 | vsetvli_e8mf2tama |
| 12 | vmseq_vi |
| 10 | vse16_v, vse32_v |
| 10 | vse32_v, vse32_v |
| 9 | vsetvli_e8mf8tama, vse64_v |
| 8 | vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmseq_vi |
| 8 | vsetvli_e8mf4tama, vle32_v, vmsne_vv |
| 8 | vle8_v, vse16_v, vse8_v |
| 7 | vse16_v, vse64_v |
| 7 | vse8_v, vse32_v |
| 5 | vse32_v, vse64_v |
| 5 | vsetvli_e8mf2tama, vsetvli_e8mf2tama |
| 5 | vsetvli_e8mf8tama, vse8_v, vse32_v |
| 5 | vle32_v, vsetvli_e8mf8tama, vse8_v |
| 4 | vle32_v, vmseq_vi |
| 4 | vle32_v, vse32_v |
| 4 | vsetvli_e8mf8tama, vse32_v, vse8_v |
| 4 | vle8_v, vsetvli_e8mf2tama, vse8_v |
| 4 | vsetvli_e8mf8tama, vsetvli_e8mf8tama, vse32_v, vse8_v |
| 4 | vse16_v, vle8_v, vse8_v |
| 4 | vsetvli_e8mf4tama, vmseq_vi |
| 4 | vsetvli_e8mf4tama, vle32_v, vsetvli_e8m1tama |
| 4 | vsetvli_e8mf4tama, vsetvli_e8m1tama, vse32_v |
| 4 | vsetvli_e8mf4tama, vle32_v, vle32_v, vsetvli_e8m1tama |
| 4 | vsetvli_e8mf2tama, vse16_v |
| 4 | vse16_v, vse16_v |
| 4 | vse8_v |
| 3 | vle32_v, vle32_v, vle32_v |
| 3 | vl1re32_v |
| 3 | vsetvli_e8mf8tama, vse16_v, vse8_v |
| 3 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v |
| 3 | vle32_v, vse16_v |
| 3 | vle64_v, vse32_v |
| 3 | vle16_v, vse32_v |
| 3 | vsetvli_e8mf4tama, vse8_v |
| 3 | vse32_v, vse64_v, vse32_v, vse32_v |
| 3 | vle64_v, vle64_v, vle64_v, vle64_v, vle64_v, vle64_v, vle64_v, vle64_v, vle64_v, vle64_v, vle64_v, vle64_v |

**Unhandled loop instructions**

Handled vector instructions each have a lambda expression providing for their basic semantics.
Unhandled instructions have no such lambda defined, and can not be used in a transform match.

The most common 50 are:

| count | unhandled instructions |
| -: | :-------- |
| 512 | vsetvli_e32m1tama |
| 332 | vsetvli_e64m1tama |
| 305 | vmv_v_x |
| 304 | vsetvli_e32mf2tama |
| 277 | vid_v |
| 266 | vmv_v_i |
| 243 | vadd_vv |
| 235 | vsetvli_e16mf4tama |
| 231 | vnsrl_wi |
| 223 | vor_vv |
| 209 | vzext_vf2 |
| 181 | vmv_x_s |
| 170 | vsetvli_e16mf2tama |
| 167 | vsll_vi |
| 157 | vsetivli_e32mf2tama |
| 153 | vmul_vx |
| 136 | vadd_vi |
| 136 | vadd_vx |
| 134 | vcompress_vm |
| 133 | vand_vv |
| 126 | vmv1r_v |
| 124 | vmv_s_x |
| 117 | vsrl_vi |
| 98 | vand_vi |
| 87 | vsll_vv |
| 86 | vsetvli_e16m1tama |
| 85 | vmerge_vim |
| 84 | vcpop_m |
| 81 | vxor_vv |
| 81 | vsetivli_e16mf4tama |
| 80 | vzext_vf4 |
| 71 | vmsne_vi |
| 68 | vslideup_vi |
| 65 | vsetivli_e32m1tama |
| 64 | vrsub_vi |
| 62 | vwredsumu_vs |
| 57 | vluxei64_v |
| 52 | vsetivli_e8mf8tama |
| 50 | vrgather_vv |
| 48 | vsrl_vv |
| 45 | vrgatherei16_vv |
| 38 | vsetivli_e64m1tama |
| 37 | vsuxei64_v |
| 34 | vredor_vs |
| 34 | vsetivli_e8m1tama |
| 33 | vlseg4e32_v |
| 32 | vslidedown_vi |
| 31 | vwaddu_wv |
| 31 | vmseq_vv |
| 30 | vsub_vv |
