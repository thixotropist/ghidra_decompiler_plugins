---
title: Large Executable Testing
description: Repeated testing of large executable binaries helps prioritize plugin development.
weight: 120
---

Plugins are tested against small datatest samples, but they show their value in making
decompilations of large binaries easier to understand and triage for relevance.

This project uses three large RISC-V executables to help drive Ghidra evolution:
* The whisper.cpp voice to text application to model inference engine applications.
* One of the Data Plane Development Kit examples to model real time networked systems.
* The Linux kernel, specifically the subsystem capable of self-modifying code based on
  the environment.  (That's currently used in rewriting encrypted storage handlers after detecting
  support for processor cryptographic and compression instructions.)

A good plugin should be useful in all three contexts, producing decompiler output that is better
than the default decompiler results in at least 98% of the functions examined.  If that
number is less than 98%, then we want to turn the failing functions into stand-alone data tests
and see how to improve the plugin's performance.

## whisper.cpp testing

### collect data

First we need to download the whisper binary from Google Drive, using the gdown application:

```console
$ gdown https://drive.google.com/file/d/11IirnOgqFs968q1XrBsohLMcinGaZ-tv/view?usp=drive_link
Downloading...
From: https://drive.google.com/uc?id=11IirnOgqFs968q1XrBsohLMcinGaZ-tv
To: /tmp/whisper_cpp_rva23
$ readelf -A /tmp/whisper_cpp_rva23
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_v1p0_zicsr2p0_zifencei2p0_zmmul1p0_zaamo1p0_zalrsc1p0_zfa1p0_zca1p0_zcb1p0_zcd1p0_zba1p0_zbb1p0_zbc1p0_zbkb1p0_zbkc1p0_zbkx1p0_zvbb1p0_zvbc1p0_zve32f1p0_zve32x1p0_zve64d1p0_zve64f1p0_zve64x1p0_zvkb1p0_zvkg1p0_zvkn1p0_zvknc1p0_zvkned1p0_zvkng1p0_zvknhb1p0_zvks1p0_zvksc1p0_zvksed1p0_zvksg1p0_zvksh1p0_zvkt1p0_zvl128b1p0_zvl32b1p0_zvl64b1p0"
  Tag_RISCV_priv_spec: 1
  Tag_RISCV_priv_spec_minor: 11
```
* Make sure a plugin-enabled decompile executable is in the Ghidra search path
    * nominally something like `/opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64`
* Build the plugin and copy it to a convenient directory, nominally `/tmp`.
* Import `whisper_cpp_rva23` into Ghidra using a RISC-V language supporting most instruction set extensions.
* launch ghidra with an environment variable identifying the plugin location
    ```console
    $ DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
    ```

Now find the total number of functions in the executable.
* The `About whisper_cpp_rva23` window claims 1914 functions
* The `Functions` window names 1708 functions, about 210 of which appear to be thunks
  and not very interesting.

We'll simplify the test and say that there are 1500 non-trivial functions in this executable.

In Ghidra select `File`⇒`Export Program` ⇒`C/C++` with output to `/tmp/whisper_cpp.c`.  The decompilation output
should be about 5.7 MB.

We should see something like:

```text
/tmp$ ls -alt
total 452220
ghidraRiscvLogger_767618.log
ghidraRiscvLogger_767622.log
ghidraRiscvLogger_767604.log
ghidraRiscvLogger_767620.log
ghidraRiscvLogger_767673.log
ghidraRiscvLogger_767606.log
ghidraRiscvLogger_767608.log
ghidraRiscvLogger_767612.log
ghidraRiscvLogger_767616.log
ghidraRiscvLogger_767651.log
whisper_cpp_rva23.c
riscv_summaries_767651.txt
riscv_summaries_767606.txt
riscv_summaries_767612.txt
riscv_summaries_767604.txt
riscv_summaries_767616.txt
riscv_summaries_767618.txt
riscv_summaries_767673.txt
riscv_summaries_767620.txt
riscv_summaries_767608.txt
riscv_summaries_767622.txt
ghidraRiscvLogger_767610.log
riscv_summaries_767610.txt
ghidraRiscvLogger_767624.log
riscv_summaries_767624.txt
ghidraRiscvLogger_767110.log
riscv_summaries_767110.txt
```

Ghidra started 10 decompile processes during this export, taking advantage of a multi-core processor and recovering from a couple of decompiler crashes.

Review the recovered C code in `whisper_cpp_rva23.c` to look for failures:

```console
$ grep 'Decompiler process died' whisper_cpp_rva23.c
Cause: Exception while decompiling ram:00032aee: Decompiler process died
Cause: Exception while decompiling ram:000cbaca: Decompiler process died
$ grep 'Low-level Error:' whisper_cpp_rva23.c
Low-level Error: Unable to force merge of op at 0x00020748:8a2
...
Low-level Error: Free varnode has multiple descendants
...
Low-level Error: Missing function callspec
...
```
There are four classes of error:
* 2 Exceptions
* 37 'Low-level Error: Unable to force merge of op'
* 2 'Low-level Error: Free varnode has multiple descendants'
* 24 'Low-level Error: Missing function callspec'

And four types of transforms making it to the C file:
* 840 `vector_memcpy`
* 278 `vector_memset`
* 51 `vector_strlen`
* 13 `vector_strcmp`

### generate new datatests

With four classes of error we want to add at least four new datatests.

* close the plugin-enabled Ghidra and start Ghidra without a plugin
* review the `whisper_cpp_rva23.c` output to identify the function names
  throwing errors.
* for each type of error, pick a single function that is fairly small
* export that function as a debug XML file, noting the function signature
  Ghidra assigned.

At this point you should have four XML decompiler debug files, ready to be transformed into
four or more datatests.

For each XML file:
* remove any coretypes and savestate elements, replacing the coretype element with `test_data/core_types.xml`.
* format the XML file with `xmllint --format` or something similar
* save it in the `test_data` directory with a name like `whisper_sample_14_save.xml`.
* generate a datatest script file with a name like `whisper_sample_14.ghidra`, using existing datatest script files as a template.
* edit the script file so that the function signature, if present, names no types not present in `test_data/core_types.xml`.

You can adjust these new four new datatests by adding variant scripts to go with a single save file.
For example, manual inspection of the two `Free varnode` failures show a common problem.  Ghidra has misidentified the function signature
as returning a 16 byte value instead of an 8 byte value.  The scalar register `a1` was used in a vector loop and should have been considered
dead at that point.  Instead, Ghidra thought it was part of a 16 byte return value returned in two registers, `a0` and `a1`.
The plugin should have recognized that descendent usage and refused to complete the transform.  We can test for that with two
Ghidra scripts loading the same save file, one with the default function signature and one with a corrected function signature.

### update integrationTest.py

We now have five new tests, `whisper_sample_13a.ghidra`, `whisper_sample_13b.ghidra`, `whisper_sample_14.ghidra`,
`whisper_sample_15.ghidra`, and `whisper_sample_16.ghidra`.  Of these, `whisper_sample_13b.ghidra` should currently pass while
the others currently fail.  Add them to the integrationTest.py in the appropriate sample sets.

### debugging

Using the new datatests helped to isolate the error - a failure to properly trace descendent varnodes of scalar operations within the loop.
That took several hours and a single line of effective source code (not counting many lines of logging and inspection).

Rebuild and repeat the full executable tests:

| Error tag | Previous test | Revised test |
| --------- | ------------- | ------------ |
| Exceptions | 2 | 1 |
| Low-level Error: Unable to force merge of op | 37 | 35 |
| Low-level Error: Free varnode has multiple descendants | 2 | 1 |
| Low-level Error: Missing function callspec | 24 | 0 |
| Total | 65 | 37 |

| Vector transforms completed | Previous test | Revised test |
| --------- | ------------- | ------------ |
| vector_memcpy | 840 | 909 |
| vector_memset | 278 | 388 |
| vector_strlen | 51 | 51 |
| vector_strcmp | 13 | 14 |
| Total | 1182 | 1362 |

That suggests that we are down to a 2.5% decompiler failure rate.
