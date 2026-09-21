---
title: Tutorials and Walkthroughs
linkTitle: Walkthroughs
description: |
   What is the utility of a sample Ghidra decompiler extension?  We show several walkthroughs analyzing RISC-V
   executables using ratified RISC-V Vector extensions as examples.  The benefits shown include more intuitive
   decompiler output and generated surveys of vector instruction sequences.
weight: 10
---

{{% blocks/section color='white' %}}

Outline:

* Show how to build a plugin, linking to a more detailed [workspace]({{< relref "../Workspace/_index.md" >}}) description.
* Show how to configure the integration test with external directories and internal log levels.*
* Build the plugin via the integration test.
* Show how to launch the plugin when starting Ghidra
* Show how to exercise the plugin via datatests
* Run the memcpy example, showing output, logs, and surveys
* Repeat with a more complex `main` example
* Repeat with a vendor-optimized Spacemit example
* Repeat with a full-binary example

## Building a plugin

The plugin source repository can be anywhere on your computer.  For this example, we will use `~/projects/github/ghidra_decompiler_plugins`
as the local clone of `git@github.com:thixotropist/ghidra_decompiler_plugins.git`.

### Configuration of the plugin build directory

#### Configuring the integration test

This project performs or verifies a proper plugin build via the Python `integration_test.py` file.  It likely needs modification
to configure the location of key resources on the installation computer.

The Ghidra runtime environment should be installed locally.  For this example we will use `/opt/ghidra_12.2_DEV` as the installation directory.
Note that this installation directory provides the Ghidra GUI, processor-specific SLEIGH files, and the baseline decompiler executable.  This project
will replace that decompiler executable with one built from a patched instance of a separate Ghidra source distribution.

Update `integration_test.py` to:

```py
GHIDRA_INSTALL_DIR = "/opt/ghidra_12.2_DEV/"
```

This installation directory normally provides the decompiler and related OS-specific executables.  This location is provided in
`integration_test.py` as:

```py
DECOMPILER_DIR = GHIDRA_INSTALL_DIR + "Ghidra/Features/Decompiler/os/linux_x86_64/"
```

This directory should be made writable by the user, as the decompiler executable will be replaced within `integration_test.py`.

The integration test will build and install the plugin to a named directory.  We use `/tmp`.

```py
PLUGIN_LOAD_DIR = "/tmp/"
PLUGIN_NAME = "libriscv_vector.so"
PLUGIN_PATH = PLUGIN_LOAD_DIR + PLUGIN_NAME
```

#### Configuring the plugin

Set the logging level for the plugin:

```cpp
///plugins/riscv.cc
static const spdlog::level::level_enum LOG_LEVEL = spdlog::level::warn; ///< default log level to use
```

Adjust if needed requests for additional survey data:

```cpp
/* in file plugins/riscv.hh */
static const bool SURVEY_ACTION_DATABASE = false; ///<@brief report on Actions available and triggered
/// @brief True if we need to collect epilog sequences from potential vector_strlen sequences
static const bool COLLECT_STRLEN_SAMPLES = true;
/// @brief True if we need to collect epilog sequences from potential vector_strcmp sequences
static const bool COLLECT_STRCMP_SAMPLES = true;
/* in file plugins/inspector.hh */
/// @brief Do we want to audit Varnode data structures for consistency?
static const bool audit_varnodes = false;
/// @brief Do we want to audit BlockGraph data structures for consistency?
static const bool audit_block_graph = false;
/// @brief Do we want to audit MULTIEQUALS and their correlation to input edges?
static const bool audit_multiequals = false
/// @brief if true, log full blocks during any blockgraph edits
bool logBlockStructure = true;
```

Adjust the destination directory and paths for logs and survey data. The default directory will be `/tmp` with filenames including the process ID of the
decompiler instance generating the report.

```cpp
/* in file plugins/riscv.cc */
std::string logFile = "/tmp/ghidraRiscvLogger_" + std::to_string(getpid()) + ".log";
std::string summariesFilename = "/tmp/riscv_summaries_" + pidAsString + ".txt";

std::string fn = "/tmp/vector_strlen_summaries_" + pidAsString + ".txt";
riscv_vector::strlenSampleFile.open(fn);

std::string fn = "/tmp/vector_strcmp_summaries_" + pidAsString + ".txt";
riscv_vector::strcmpSampleFile.open(fn);
```

### Compiling and linking the plugin

The python integration test builds (or verifies from cache) plugin dependencies and then compiles and links the
plugin, then copies it into `/tmp` for use.  The individual compilation, copy, and Ghidra startup steps are:

```console
$ bazelisk build -c dbg plugins:riscv_vector
...
  bazel-bin/plugins/libriscv_vector.so
```

This `bazelisk` command builds the plugin sharable object module `libriscv_vector.so` using the sources within
the `plugin` directory.  It will link those sources against a patched remote Ghidra source repository.

```console
$ cp -f bazel-bin/plugins/libriscv_vector.so /tmp
```

The plugin is then copied into an arbitrary directory.

```console
$ DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
```

The new environment variable `DECOMP_PLUGIN` is passed into Ghidra, which passes it into decompiler executions.
The patched decompiler will search for a plugin of that name and integrate any Actions and Rules it may provide.

## Exercising the plugin

Ghidra will load and exercise the plugin two ways:
* as part of a full Ghidra GUI session launched by `ghidraRun`
* within a `decompile_datatest` when launched by
  `SLEIGHHOME=/opt/ghidra_12.2_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest`

We'll use both methods in this tutorial/walkthrough.

### A minimal vector_memcpy walkthrough

One of the most common vector patterns copies memory from one location to another. Vector instructions can be useful with as few as two bytes of data
to be copied, if the alignment of those bytes is unknown at compile time.

The `test_data/memcpy_exemplars.ghidra` datatest includes the function `void memcpy_i2(char* to, char* from)` to implement a two-byte unaligned copy.

```as
memcpy_i2:
    vsetivli zero,0x2,e8,mf8,ta,ma
    vle8.v   v1,(a1)
    vse8.v   v1,(a0)
    ret
```

This is a datatest, so we can exercise the datatest *without a plugin* using a command like:

```console
$ SLEIGHHOME=/opt/ghidra_12.2_DEV/ /opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < \
   test_data/memcpy_exemplars.ghidra
```

The resulting decompilation is:

```c
void memcpy_i2(void *to,void *from)

{
  undefined1 auVar1 [32];

  vsetivli_e8mf8tama(2);
  auVar1 = vle8_v(from);
  vse8_v(auVar1,to);
  return;
}
```

Repeat with the plugin by adding the plugin location:

```console
$ SLEIGHHOME=/opt/ghidra_12.2_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so \
   /opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < \
   test_data/memcpy_exemplars.ghidra
```

The plugin changes the decompilation to something easier to interpret:

```c
void memcpy_i2(void *to,void *from)

{
  vsetivli_e8mf8tama(2);
  vector_memcpy((void *)to,(void *)from,2);
  return;
}
```

The plugin generates logs and survey files to `/tmp`, with the decompiler process ID embedded within the name:
* `riscv_summaries_771775.txt`:
    ```
    RISC-V Summary Report
    Vector Series:
        Sequence start address: 0x0
        vset op: vsetivli_e8mf8tama
        element size: 1
        number of bytes: 2
        vector loads: 1
        Load op at 0x4 has a valid dependent vector store op at 0x8
    ```
* `ghidraPluginManager.log` is empty because the decompiler through no errors when attempting to load the plugin
* `vector_strcmp_summaries_771775.txt` and `vector_strlen_summaries_771775.txt` are empty because there were no `strcmp` or `strlen`
  sequences found
* `ghidraRiscvLogger_771775.log` is empty because the plugin generated no log messages of `warn` or higher severity.

### A minimal vector_memcpy with block editing walkthrough

The `test_data/memcpy_exemplars.ghidra` datatest also includes the function `void memcpy_v(char* to, char* from, uint size)` to implement a variable length unaligned copy.

Without enabling the plugin, the decompilation is:

```c
void memcpy_v1(void *to,void *from,long size)

{
  long lVar1;
  undefined1 auVar2 [32];

  do {
    lVar1 = vsetvli_e8m1tama(size);
    auVar2 = vle8_v(from);
    size = size - lVar1;
    to = (void *)((long)to + lVar1);
    vse8_v(auVar2,to);
    from = (void *)((long)from + lVar1);
  } while (size != 0);
  return;
}
```

With the plugin enabled, we get instead:

```c
void memcpy_v1(void *to,void *from,long size)

{
  vector_memcpy((void *)to,(void *)from,size);
  return;
}
```

This shows how an entire block (the `do ... while` block before the plugin transform) can be replaced with a single function call.

The `riscv_summaries` survey report for this loop shows the loop traits that select for a `vector_memcpy` transform attempt:

```text
Vector Loop (simple):
        control structure is simple
        Loop start address: 0x48
        Loop length: 0x12
        Loop traits: 0x7
        setvli mode: element size=1, multiplier=1
        vector instructions: 3
        vector loads: 1
        vector stores: 1
        integer arithmetic ops: 4
        scalar comparisons: 1
        vector logical ops: 0
        vector integer ops: 0
        vector comparisons: 0
        vector source operands: 1
        vector destination operands: 1
        edges in: 1
        Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | ?,
        Loop control variable: a2(0x00000050:3) = a2(0x00000048:e) + u0x10000000(0x00000050:11)
        Loop Local-scope Varnodes: a3(0x00000048:0), u0x10000000(0x00000050:11), a2(0x00000050:3), a0(0x00000052:4), a1(0x00000058:7), a1(0x00000048:d), a0(0x00000052:4), a2(0x00000050:3),
```

### A survey report for a very complex loop

Inference Engines spend a lot of cycles performing vector dot products, especially with vector elements representing weights with fewer than 32 bits of floating point precision.

The llama function `ggml_vec_dot_q4_K_q8_K_vl256` is an example important enough for SpaceMit to hand-optimize using RISC-V C intrinsics.  This example is far to complex for the gcc compiler
to vectorize automatically or for the plugin to translate into more comprehensible C code.  The plugin survey feature can be useful here, helping the Ghidra user search for and possibly
recognize a key IE function.

>Note: See [Analysis of complex loops]({{< relref "../notes/Analysis_of_complex_loops.md" >}}) for more details.

```console
$ SLEIGHHOME=/opt/ghidra_12.2_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so \
  /opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < \
  test_data/ggml_vec_dot_q4_K_q8_K_vl256.ghidra
...
```

The survey report for that function is:

```text
Vector Loop (simple):
        control structure is simple
        Loop start address: 0x106306
        Loop length: 0x222
        Loop traits: 0x10a902f
        setvli mode: element size=2, multiplier=2
        vector instructions: 70
        vector loads: 16
        vector stores: 1
        integer arithmetic ops: 34
        scalar comparisons: 1
        vector logical ops: 0
        vector integer ops: 0
        vector comparisons: 0
        vector source operands: 16
        vector destination operands: 1
        edges in: 1
        Vector instructions (handled | unhandled | epilog): vle8_v, vsetivli_e16mf2tama, vlse16_v, vlse16_v, vsetvli_e8m1tama, vle8_v, vsetivli_e8m1tama, vse8_v, vsetvli_e8m1tama, vle8_v, vsetivli_e16mf2tama, vadd_vv, vsetvli_e8m1tama, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vle8_v, vsrl_vi, vsrl_vi, vsrl_vi, vand_vi, vand_vi, vand_vi, vand_vi, vsrl_vi, vsetivli_e8mf4tama, vle8_v, vsetvli_e8m1tama, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vwmul_vv, vsetvli_e16m2tama, vredsum_vs, vredsum_vs, vredsum_vs, vredsum_vs, vredsum_vs, vredsum_vs, vsetivli_e16mf2tama, vzext_vf2, vsetvli_e16m2tama, vredsum_vs, vredsum_vs, vsetivli_e16mf2tama, vmv_x_s, vmv_x_s, vwmul_vv, vmv_x_s, vmv_x_s, vsetvli_e32m1tama, vredsum_vs, vsetivli_e16m1tama, vmv_x_s, vmv_x_s, vsetivli_e32m1tama, vmv_x_s, vsetivli_e16m2tama, vmv_x_s, vmv_x_s, | | ?,
        Loop control variable: u0x00031600:4(0x001064f6:13f) = t3:4(0x00106306:24e) + #0x1:4
        Loop Local-scope Varnodes: a4(0x0010630a:51), a4(0x0010631a:59), a0(0x0010632e:63), a4(0x00106336:67), a7(0x0010633a:69), t1(0x0010633e:6b), a4(0x00106356:76), a4(0x00106362:82), a7(0x00106372:8a), a4(0x00106376:8c), s2(0x00106382:92), t1(0x00106392:9c), s2(0x00106396:9e), u0x00027400:4(0x0010645e:ee), u0x00027400:4(0x0010647a:f8), u0x00027400:4(0x00106496:104), u0x00020c00:4(0x001064a2:109), u0x00027400:4(0x001064b2:112), u0x00099900(0x001064c6:11b), u0x00027400:4(0x001064cc:121), u0x00020c00:4(0x001064d6:127), u0x00015b00(0x001064da:12a), u0x00099900(0x001064e2:130), u0x00027400:4(0x001064e6:133), u0x00020c00:4(0x001064f2:13c), u0x00031600:4(0x001064f6:13f), u0x00027400:4(0x00106500:14e), a2(0x00106506:154), u0x00020c00:4(0x0010650a:155), a3(0x0010650e:158), u0x00027400:4(0x00106512:159), u0x00020c00:4(0x00106516:15b), u0x00020c00:4(0x0010651a:15d), u0x00031900:4(0x0010651e:15f), a2(0x00106306:1c9), a4(0x0010630a:51), a3(0x00106306:1ca), a4(0x0010631a:59), a0(0x0010632e:63), a4(0x00106336:67), a4(0x00106356:76), a7(0x0010633a:69), t1(0x0010633e:6b), a4(0x00106362:82), a7(0x00106372:8a), a4(0x00106376:8c), s2(0x00106382:92), s2(0x00106396:9e), t1(0x00106392:9c), s1(0x001062fa:255), sp(0x001062b2:254), u0x00031600:4(0x001064f6:13f),
```

Key points include:
* with a single loop length of 0x222 bytes (546 decimal), this is a large block.
* with 16 vector loads and 1 vector store, this suggests some sort of striping or loop unrolling is present.
* the 'multiplier=2 term means that at least one vset* instruction is grouping vector registers.
* the multiple `vredsum_vs` instructions suggests that this is an unrolled reduction operation, taking vector arguments and producing a scalar result.

### Two large main routines

Examining a large executable binary often starts with applying Ghidra to the `main` function.  This walkthrough starts with the `main` function of something
that you might not expect to benefit much from vector instructions, the main routine of `dpdk-l3fwd` compiled with `-O2` optimization.

This function includes four vector loops, which the plugin helps render as:

```c
  if (lookup_mode == 2) {
LAB_ram_001bcdb0:
    vector_memcpy((void *)(unaff_s7 + 3),(void *)(unaff_s2 + 0x360),0x40);
  }
  else if (lookup_mode == 3) {
    vector_memcpy((void *)(unaff_s7 + 3),(void *)(unaff_s2 + 0x3a0),0x40);
  }
  else if (lookup_mode == 4) {
    vector_memcpy((void *)(unaff_s7 + 3),(void *)(unaff_s2 + 0x3e0),0x40);
  }
  else {
    vector_memcpy((void *)(unaff_s7 + 3),(void *)(unaff_s2 + 0x420),0x40);
  }
```

Next we examine the main routine of `whisper-cpp`, something that is very likely to be compiled with vector support and full optimization.

This `main` routine (size of 10KB) shows many vector transforms:

```c
vector_memset((void *)&whisper_params.field_0x48,0,0x10);
vector_memcpy((void *)&whisper_params.field_0x2c,(void *)0x107f20,0x10);
vector_memcpy((void *)&whisper_params.field_0x3c,(void *)0x107a18,8);
vector_memcpy((void *)&whisper_params.field_0x58,(void *)0x107a20,8);
vector_memset((void *)&local_a0,0,0x10);
vector_memcpy((void *)((long)local_8f0 + 0x10),(void *)local_4a8,(ulong)(local_4a0 + 1));
vector_memcpy((void *)auStack_6b0,(void *)&whisper_params.field_0x5d,2);
vector_memcpy((void *)auStack_760,(void *)auStack_6b0,0x30);
vector_memset((void *)avStack_650,0,0x10);
vector_memcpy((void *)&local_6c8,(void *)&local_a0,0x10);
vector_memcpy((void *)&local_a0,(void *)avStack_650,0x10);
vector_memcpy((void *)psVar20,(void *)local_4c8,(ulong)pwVar43);
vector_memset((void *)avStack_650,0,0x10);
vector_memcpy((void *)local_878,(void *)&local_a0,0x10);
vector_memcpy((void *)&local_a0,(void *)avStack_650,0x10);
vector_memcpy((void *)local_568,(void *)puVar37,uVar8);
vector_memcpy((void *)local_548,(void *)puVar37,(ulong)pwVar43);
psVar16 = (string *)vector_strlen((char *)psVar35);
vector_memcpy((void *)local_4c8,(void *)ppwVar5,(ulong)pwVar43);
vector_memcpy((void *)(local_4c8 + (long)pwVar43),(void *)0xfe068,10);
uVar13 = vector_strlen((char *)pcVar22);
```

Note that this list includes `memset`, `memcpy`, and `strlen` patterns.  The `memcpy` instances include both fixed-length and variable length copies.
The survey report shows 9 vector loops identified.  The log file shows some failed transforms,

```c
  do {
    lVar19 = vsetvli_e8m1tama(lVar18);
    auVar46 = vle8_v(pvVar33);
    lVar18 = lVar18 - lVar19;
    pvVar33 = pvVar33 + lVar19;
    vse8_v(auVar46,puVar37);
    puVar37 = puVar37 + lVar19;
  } while (lVar18 != 0);
  local_5e0 = &local_6e0;
                    /* try { // try from 00021b7a to 00021b7d has its CatchHandler @ 00023e20 */
  lVar18 = whisper_full_parallel
                     (lVar17,auStack_870,local_710,(long)(int)(local_708 - (long)local_710 >> 2),
                      (long)(int)whisper_params._4_4_,lVar19,puVar37,pvVar33);
```

This commonly occurs when a vector loop is followed by a function call whose parameter list has not been committed.
In this instance, `whisper_full_parallel` only takes five parameters, not the seven parameters shown.  The last two bogus
parameters match temporary registers used within the vector loop.  If we commit the five-parameter `whisper_full_parallel`
signature the transform completes with:

```c
  vector_memcpy((void *)auStack_870,(void *)local_880,0x108);
  local_5e0 = &local_6e0;
                    /* try { // try from 00021b7a to 00021b7d has its CatchHandler @ 00023e20 */
  lVar19 = whisper_full_parallel
                     (lVar18,(long)auStack_870,(long)local_710,
                      (int)(local_708 - (long)local_710 >> 2),(long)(int)whisper_params._4_4_);
```

### Full executable export to C

The preceding examples show decompiler plugin results for a single function.  We can also export an entire binary to
C through the Ghidra GUI.  For this example we'll use the full executable `dpdk-l3fwd` compiled with `-O2` optimization.

The Ghidra GUI menu provides `File ⇒ Export Program ⇒ C/C++` to accomplish this.

First, collect some size data from the executable:

* 2.6M instructions
* 24K functions
* built with GCC 15.2

The C exported source code shows these traits:

* 48 MB in `dpdk-l3fwd-O2.c`
* `sloccount` reports 1.5M lines of code

The plugin produces 52 files - 13 sets of `ghidraRiscvLogger`, `riscv_summaries`, `vector_strlen_summaries`, and `vector_strcmp_summaries`.
The Ghidra GUI has spawned 13 instances of the decompiler process.  Most of these are to take advantage of the number of cores on
the test computer, with a few more spawns due to the decompiler crashing on specific functions.

We can get a good survey of the way this function uses vector instructions with one of the tools in our `script` directory.

The invocation and first report section look like this:

```markdown
$ scripts/process_analytics.py dpdk-l3fwd-O2 full
# Analysis of dpdk-l3fwd-O2 RISC-V Transform results

## Analysis of C/C++ export file

### Scanning /tmp/dpdk-l3fwd-O2.c

* Unable to decompile 'rte_swx_ctl_meter_profile_delete'
* Unable to decompile 'eal_memalloc_mem_event_callback_unregister'
* Unable to decompile 'eal_memalloc_mem_alloc_validator_unregister'
* Unable to decompile 'get_event_config'
* Unable to decompile 'eth_igb_rss_reta_query'
* Cause: Exception while decompiling ram:00550058: Decompiler process died
* Unable to decompile 'eth_igc_rss_reta_query'
* Cause: Exception while decompiling ram:0055c05c: Decompiler process died
* Unable to decompile 'iavf_get_qos_cap'
* Unable to decompile 'nfp_net_reta_query'
* Cause: Exception while decompiling ram:0065355c: Decompiler process died
* Unable to decompile 'nfp_net_get_eeprom'
* Unable to decompile 'qede_fw_version_get'
* Unable to decompile 'virtio_init_device'
* Unable to decompile 'vhost_vdpa_get_config'
* Unable to decompile 'virtio_crypto_pkt_tx_burst'
* Unable to decompile 'vhost_vdpa_get_config'
```

This section tells us:
* Three functions out of 24K total functions generated an exception in the decompiler.
  This is likely due to a known decompiler bug that places PcodeOps in the incorrect Block,
  causing a low-level exception when that block is transformed.
* 14 functions out of 24K total fail to decompile without crashing the decompiler process.
  This is often due to the size of the function, causing the decompiler to fail during bulk
  exports.  Many of these will decompile correctly within the Ghidra decompiler window.

The next section summarizes the transforms completed.

```markdown
### Summary counts
The export C source code shows successful vector transforms.  The `vector_memcpy` and
`vector_memset` transforms can be formed from either vector series or simple vector loops.
The `vector_strlen` and `vector_strcmp` are only found in simple vector loops.

| count |transform |
| ---: | :------------ |
| 6811 | vector_memcpy |
| 1740 | vector_memset |
| 191 | vector_strlen |
| 721 | vector_strcmp |

>Note: Also found 11067 other vsetvli or vsetivli instructions
```

Next we get an analysis of the 13 logger files.

```markdown
## Analysis of transform logger file /tmp/ghidraRiscvLogger.log

This plugin generates warnings when it can no longer continue with a transform attempt.

### Warning summary counts

| count | text |
| ---: | :------------- |
| 3356 | Failed to extract Vector load pExternal varnode |
| 2588 | Unable to fully analyze potential complex vector loop stanza |
| 2279 | Failed to extract Vector store pExternal varnode |
| 1488 | Unable to complete transform due to reference to loop-local Varnode |
| 1231 | Unrecognized number of vector pcode arguments |
| 1014 | Unable to complete transform due to one or more references to a loop-local Varnode |
| 88 | Vector vset found with no output register |
| 44 | Failed to collect source register from a vector load operation |
| 4 | Unrecognized number of scalar pcode arguments |
```

These warnings usually indicate a vector stanza looked superficially like a candidate for
a vector transform, but the transform code ran into something unexpected that prevented
a completed transform.  This can happen for many reasons, and suggests what parts of the
plugin code might be improved next.

The next section collects vector sequences in simple (single block) vector stanzas.
The first two lines of the table of sequences are the most useful here:

* 3272 blocks looked like `vector_memcpy` sequences but were not transformable.  The
  root cause might be related to the 3356 warnings about being unable to extract the
  vector load Varnode in the previous section
* 877 blocks look like `vector_strncmp` sequences.  We don't handle these yet because
  the loop actually spans two Ghidra blocks and we haven't learned how to transform
  more than a single block.

```markdown
## Analysis of loop and series summary file

**Simple loop signatures**

Simple loops consist of a single Ghidra block with no internal jumps or calls other than
the conditional branch returning to the start of the block.  Builtins like `memcpy` and
`strcmp` generally result in simple loops.

Recognized (aka 'handled') vector instruction sequences are found in simple loop bodies:
The most common 50 are:

| count | handled instructions |
| ---: | :-------- |
| 3272 | vsetvli_e8m1tama, vle8_v, vse8_v |
| 877 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmsne_vv, vmseq_vi, vmor_mm, vfirst_m |
| 252 | vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m |
| 12 | vsetvli_e16m1tama, vle8_v, vzext_vf2, vse16_v |
| 4 | vsetvli_e64m1tama, vle64ff_v, vmseq_vi, vfirst_m |
| 4 | vsetvli_e8mf4tama, vle32_v, vsetvli_e8m1tama, vrgatherei16_vv, vsetvli_e32m1tama, vse32_v |
| 4 | vsetvli_e8m1tuma, vle8_v, vxor_vv, vor_vv |
| 4 | vsetvli_e16mf2tama, vnsrl_wi, vse16_v, vsetvli_e32m1tama, vmv_v_x, vadd_vv |
| 4 | vsetvli_e16mf2tama, vnsrl_wi, vsetvli_e8mf4tama, vand_vi, vnsrl_wi, vsrl_vi, vrsub_vi, vsll_vv, vor_vv, vsetvli_e32m1tama, vadd_vi |
| 4 | vsetvli_e64m1tama, vle64_v, vadd_vv, vse64_v |
| 3 | vsetvli_e8mf2tama, vse16_v |
| 3 | vsetvli_e8mf4tama, vse32_v |
| 2 | vsetvli_e32m1tama, vle16_v, vsext_vf2, vsub_vv, vfcvt_fxv, vfmul_vf, vse32_v |
| 2 | vsetvli_e32m1tama, vle32_v, vsub_vv, vfcvt_fxuv, vfmul_vf, vse32_v |
| 2 | vsetvli_e8mf8tama, vle64_v, vsetvli_e8m1tama, vrgatherei16_vv, vsetvli_e64m1tama, vse64_v |
| 2 | vsetvli_e32m1tama, vle16_v, vzext_vf2, vse32_v |
| 2 | vsetvli_e64m1tama, vle64_v, vluxei64_v, vsetvli_e32mf2tama, vnsrl_wi, vsetvli_e16mf4tama, vnsrl_wi, vse16_v |
| 2 | vsetvli_e8mf2tama, vlse16_v, vse16_v |
| 2 | vsetvli_e32m1tama, vle16_v, vzext_vf2, vsub_vv, vfcvt_fxv, vfmul_vf, vse32_v |
| 2 | vsetvli_e32m1tama, vle32_v, vsub_vv, vfcvt_fxv, vfmul_vf, vse32_v |
| 2 | vsetvli_e16m1tama, vmv_v_x, vsetvli_e8mf2tama, vwaddu_wv, vmv1r_v, vmv1r_v, vsetvli_e16m1tama, vmv_v_i, vsetvli_e16m1tama, vsseg2e16_v, vmv1r_v, vsseg2e16_v |
| 2 | vsetvli_e16mf2tama, vnsrl_wi, vadd_vv, vsetvli_e32m1tama, vmv_v_x, vsetvli_e16mf2tama, vsll_vi, vse16_v, vsetvli_e32m1tama, vadd_vv |
| 2 | vsetvli_e64m2tama, vle32_v, vzext_vf2, vsll_vi, vsetvli_e32m1tama, vluxei64_v, vse32_v |
| 2 | vsetvli_e8mf2tama, vle8_v, vmseq_vi, vsetvli_e16m1tumu, vadd_vi |
| 1 | vsetvli_e32m1tuma, vle32_v, vadd_vv |
| 1 | vsetvli_e8m1tuma, vle8_v, vadd_vv |
| 1 | vsetvli_e8m1tama, vle8_v, vle8_v, vor_vv, vse8_v |
| 1 | vsetvli_e32m1tama, vle32_v, vle32_v, vmadd_vv, vse32_v |
| 1 | vsetvli_e32m1tumu, vle32_v, vle32_v, vmslt_vv, vmsne_vv, vmerge_vim, vmv1r_v, vor_vv |
| 1 | vsetvli_e8m1tama, vle8_v, vmsne_vi, vse8_v |
| 1 | vsetvli_e8m1tama, vle8_v, vmaxu_vv, vse8_v |
| 1 | vsetvli_e32m1tama, vremu_vx, vle32_v, vsetvli_e32m1tama, vmv_v_x, vsetvli_e32m1tama, vand_vi, vsetvli_e32m1tama, vadd_vv, vsetvli_e32m1tama, vand_vi, vor_vv, vse32_v |
| 1 | vsetvli_e16mf4tama, vle64_v, vluxei64_v, vsetvli_e32mf2tama, vzext_vf2, vadd_vi, vsrl_vi, vor_vv, vsrl_vi, vor_vv, vsrl_vi, vor_vv, vsrl_vi, vor_vv, vsrl_vi, vor_vv, vadd_vi, vsrl_vi, vminu_vv, vsetvli_e16mf4tama, vnsrl_wi, vsuxei64_v |
| 1 | vsetvli_e32m1tama, vzext_vf4, vxor_vv, vsrl_vi, vand_vi, vmul_vv, vsetvli_e8mf4tama, vsrl_vi, vsetvli_e32m1tama, vxor_vv |
| 1 | vsetvli_e32m1tama, vsrl_vi, vsrl_vi, vsrl_vi, vand_vi, vand_vi, vand_vi, vor_vv, vnot_v, vnot_v, vor_vv, vor_vv, vnot_v, vnot_v, vand_vv, vand_vv, vand_vv, vxor_vv, vand_vv, vand_vv, vand_vi, vor_vv, vand_vv, vand_vv, vand_vi, vand_vv, vnot_v, vand_vv, vand_vv, vxor_vv, vand_vv, vxor_vv, vor_vv, vand_vv, vxor_vv, vand_vv, vor_vv, vand_vv, vor_vv, vand_vv, vor_vv, vor_vv, vxor_vv, vand_vi, vsll_vi, vxor_vv, vand_vv, vor_vv, vor_vv, vor_vv, vsll_vi, vsll_vi, vor_vv, vsetvli_e32m1tama, vmv_v_x, vsetvli_e32m1tama, vor_vv, vse32_v, vsetvli_e32m1tama, vadd_vv |
| 1 | vsetvli_e8m1tama, vlseg4e8_v, vmv1r_v, vmv1r_v, vmv1r_v, vmv1r_v, vsseg4e8_v |
| 1 | vsetvli_e32m1tuma, vsra_vv, vadd_vv, vsrl_vv, vand_vi, vsra_vv, vsrl_vv, vmul_vv, vand_vi, vmul_vv, vxor_vv, vsetvli_e32m1tama, vmv_v_x, vsetvli_e32m1tuma, vxor_vv, vsetvli_e32m1tama, vadd_vv |
| 1 | vsetvli_e8m1tama, vle8_v, vse8_v, vle8_v, vor_vv, vnot_v, vse8_v |
| 1 | vsetvli_e64m1tama, vmv_v_x, vsrl_vv, vsrl_vv, vsetvli_e32mf2tama, vnsrl_wi, vsetvli_e64m1tama, vmv_v_x, vsetvli_e32mf2tama, vnsrl_wi, vsetvli_e16mf4tama, vnsrl_wi, vsetvli_e64m1tama, vsrl_vv, vsetvli_e16mf4tama, vnsrl_wi, vsetvli_e64m1tama, vsrl_vv, vsetvli_e16mf4tama, vand_vv, vsetvli_e32mf2tama, vnsrl_wi, vsetvli_e16mf4tama, vand_vv, vsetvli_e32mf2tama, vnsrl_wi, vse16_v, vsetvli_e16mf4tama, vse16_v, vnsrl_wi, vnsrl_wi, vand_vv, vand_vv, vse16_v, vse16_v |
| 1 | vsetvli_e32mf2tama, vle64_v, vle32_v, vwaddu_wv, vse64_v |
| 1 | vsetvli_e8mf2tumu, vlse8_v, vand_vi, vmseq_vi, vadd_vi |
| 1 | vsetvli_e32m1tumu, vle32_v, vnot_v, vadd_vi, vmsne_vi, vand_vv, vadd_vi, vsrl_vi, vand_vx, vsub_vv, vsrl_vi, vand_vx, vand_vx, vadd_vv, vsrl_vi, vadd_vv, vand_vx, vmul_vx, vsetvli_e16mf2tamu, vmv1r_v, vnsrl_wi, vadd_vi, vse16_v |
| 1 | vsetvli_e64m1tama, vle64_v, vsra_vi, vse64_v |
| 1 | vsetvli_e16mf2tumu, vlse16_v, vmv1r_v, vmsne_vi, vwaddu_wv |
| 1 | vsetvli_e32m1tama, vle8_v, vzext_vf4, vse32_v |
| 1 | vsetvli_e8m1tama, vse8_v, vsetvli_e8m1tama, vmv_v_x, vadd_vv |
| 1 | vsetvli_e32m1tama, vle32_v, vsrl_vi, vsll_vi, vsrl_vi, vsll_vi, vor_vv, vand_vv, vand_vv, vor_vv, vor_vv, vse32_v |
| 1 | vsetvli_e8mf2tama, vse16_v, vsetvli_e16m1tama, vmv_v_x, vadd_vv |
| 1 | vsetvli_e8m1tama, vle8_v, vle8_v, vand_vv, vse8_v, vle8_v, vand_vv, vse8_v |
| 1 | vsetvli_e64m1tama, vle64_v, vluxei64_v, vse64_v |
```

```markdown
**Complex loop signatures**

Complex loops consist of multiple Ghidra blocks with at least one internal jump or call other than
the conditional branch returning to the start of the block.  Builtins like `strncmp`
generally result in complex loops.

Recognized (aka 'handled') vector instruction sequences  are found in complex loop bodies:

The most common 50 are:

| count | handled instructions |
| -: | :-------- |
| 226 | vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmseq_vi, vmsne_vv |
| 40 | vsetivli_e32mf2tama, vsetvli_e16mf4tama, vmv_v_i, vse16_v |
| 38 | vsetvli_e8m1tama, vle8_v, vse8_v |
| 29 | vle16_v, vsetvli_e32m1tama, vmv_s_x, vsetivli_e16mf2tama, vwredsumu_vs, vsetvli_e32m1tama, vmv_x_s |
| 20 | vsetivli_e32mf2tama, vmv_v_i, vsetvli_e16mf4tama, vmv_v_i |
| 13 | vle16_v, vmv_s_x, vsetvli_e16mf2tama, vwredsumu_vs, vsetvli_e32m1tama, vmv_x_s |
| 11 | vsetvli_e32m1tama, vmv_v_x |
| 10 | vsetivli_e16mf4tama, vle32_v, vnsrl_wi, vsetvli_e32mf2tama, vmv_x_s, vsetivli_e8mf8tama, vnsrl_wi |
| 10 | vsetvli_e16mf4tama, vmv_v_i, vse16_v |
| 6 | vsetvli_e32m1tama, vid_v |
| 5 | vsetvli_e64m1tama, vmv_s_x |
| 5 | vsetivli_e16mf2tama, vle16_v, vsetvli_e32m1tama, vmv_s_x, vsetivli_e16mf2tama, vwredsumu_vs, vsetvli_e32m1tama, vmv_x_s |
| 5 | vsetivli_e16mf4tama, vle32_v, vnsrl_wi, vsetvli_e8mf8tama, vnsrl_wi, vse8_v |
| 4 | vsetivli_e16mf4tama, vsetvli_e64m1tama, vmv_v_i, vse64_v |
| 4 | vsetivli_e8mf8tama, vid_v, vrsub_vi, vsetvli_e32mf2tama, vmv_v_i, vse8_v, vse32_v |
| 4 | vsetvli_e64m8tama, vsrl_vi, vse64_v |
| 4 | vsetivli_e32m1tama, vle16_v, vmv_s_x, vsetvli_e16mf2tama, vwredsumu_vs, vsetvli_e32m1tama, vmv_x_s |
| 3 | vsetvli_e32m1tama, vmv_v_i |
| 3 | vsetvli_e32m1tama, vmv_s_x, vredsum_vs, vmv_x_s |
| 3 | vl8re64_v, vsll_vi, vsll_vi, vsetvli_e64m8tamu, vluxei32_v, vsetvli_e32m4tama, vsetvli_e64m8tama, vsrl_vv, vand_vx, vsrl_vi, vse64_v |
| 3 | vsetvli_e32m4tama, vle32_v, vsrl_vi, vsrl_vi, vand_vx, vsll_vi, vand_vi, vsetvli_e64m8tama, vluxei32_v, vsetvli_e32m4tama, vsll_vi, vsetvli_e64m8tama, vsrl_vv, vand_vx, vsetvli_e32m4tama, vnsrl_wi, vsetvli_e64m8tama, vand_vi, vsetvli_e32m4tama, vsll_vi, vsetvli_e64m8tama, vmseq_vi, vsetvli_e32m4tamu, vadd_vv, vcpop_m, vsrl_vi, vand_vi |
| 3 | vsetivli_e64m1tama, vsetvli_e16mf4tama, vmv_v_i, vse16_v |
| 3 | vsetivli_e32mf2tama, vid_v, vsetvli_e64m1tama, vid_v, vsetvli_e32mf2tama, vrsub_vi, vsetvli_e64m1tama, vmul_vx, vse32_v, vse64_v, vse32_v, vsetvli_e32mf2tama, vmv_v_i, vse32_v |
| 3 | vsetvli_e32mf2tama, vmv_v_i, vse32_v |
| 3 | vsetvli_e16m1tama, vid_v |
| 3 | vsetvli_e8mf2tama |
| 3 | vsetivli_e64m1tama, vsetvli_e32mf2tama, vmv_v_i, vse32_v |
| 3 | vsetvli_e8mf8tama, vid_v, vsetivli_e32m1tama, vmv_v_i, vsetivli_e8mf8tama, vrsub_vi, vse8_v, vsetivli_e32m1tama, vse32_v |
| 3 | vsetivli_e8mf8tama, vsetvli_e16mf4tama, vmv_v_i, vse16_v |
| 2 | vsetvli_e16mf4tama, vnsrl_wi, vsetvli_e32mf2tama, vmv_x_s, vsetivli_e8mf8tama, vnsrl_wi, vse8_v |
| 2 | vsetvli_e64m2tama, vmv_v_x, vsetvli_e16m2tama, vid_v, vadd_vv |
| 2 | vsetivli_e32mf2tama, vid_v, vrsub_vi, vle32_v, vrgather_vv, vsetvli_e16mf4tama, vnsrl_wi, vse16_v |
| 2 | vsetivli_e32mf2tama, vid_v, vsetvli_e64m1tama, vid_v, vsetvli_e32mf2tama, vrsub_vi, vsetvli_e64m1tama, vmul_vx, vse32_v, vse64_v |
| 2 | vsetvli_e8m1tama, vmv_s_x, vmv_v_x |
| 2 | vsetvli_e8m1tama, vredor_vs, vmv_x_s |
| 2 | vsetvli_e8m1tama, vmv_v_x, vmv_v_i |
| 2 | vsetvli_e8m1tama, vmv_s_x, vredor_vs, vmv_x_s |
| 2 | vsetvli_e8m1tama, vmv_v_i |
| 2 | vsetvli_e8m1tama, vmv_s_x, vredsum_vs, vmv_x_s |
| 2 | vsetvli_e64m2tama, vmv_v_x, vsetvli_e8mf4tama, vle32_v, vsetvli_e16m2tama, vid_v, vadd_vv, vsetvli_e8m1tama, vrgatherei16_vv, vsetvli_e32m1tama, vsse32_v |
| 2 | vsetvli_e8mf4tama, vle32_v, vsetvli_e8m1tama, vrgatherei16_vv, vsetvli_e32m1tama, vsse32_v |
| 2 | vsetivli_e32mf2tama, vmv_v_i, vsetvli_e16mf4tama |
| 2 | vsetvli_e8mf4tama, vid_v, vsetvli_e32m1tama, vzext_vf4 |
| 2 | vsetvli_e8mf4tama, vle8_v, vsetvli_e8mf4tama, vmv_v_i, vsetvli_e32m1tama, vmv_v_i |
| 2 | vsetvli_e8mf4tama, vse8_v |
| 2 | vsetivli_e16mf4tama, vid_v, vsetvli_e64m1tama, vid_v, vsetvli_e16mf4tama, vmul_vx, vsetvli_e64m1tama, vmul_vx, vsetvli_e16mf4tama, vadd_vx, vsetvli_e64m1tama, vadd_vx, vse16_v, vse64_v |
| 2 | vsetvli_e32m1tama, vid_v, vmv_x_s |
| 2 | vsetvli_e16m1tama, vmv_v_x |
| 2 | vsetvli_e16m2tama, vid_v, vrsub_vx, vsetvli_e8m1tama |
| 2 | vsetvli_e16m2tama, vid_v, vmv_v_i, vand_vi, vmseq_vi, vmseq_vi, vmseq_vi, vmerge_vim, vmseq_vi, vmseq_vi, vmerge_vim, vmseq_vi, vmerge_vim, vmv1r_v, vmerge_vim, vmv1r_v, vmerge_vim, vmv1r_v, vmerge_vim, vmseq_vi, vmerge_vim, vadd_vv |
```

{{% /blocks/section %}}