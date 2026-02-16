---
title: Survey
weight: 60
description: Survey an executable for common patterns that *may* be worth transforming.
---

>Summary: Decompiler plugins can be used to survey for patterns and help prioritize new transformation code.  This exercise
>         shows how to survey the `whisper-cpp` for vector loop stanzas that *may* be worth transforming.

# Generating raw survey files

We want to run all known functions through the decompiler, with a plugin capable of surveying likely vector stanzas.
The raw survey files will be dropped into `/tmp`.

* launch Ghidra with a survey-capable plugin:
    ```console
    $ bazel build -c dbg plugins:riscv_vector
    $ cp -f bazel-bin/plugins/libriscv_vector.so /tmp
    $ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_12.1_DEV/ghidraRun
    ```
* open `whisper_cpp_rva23` and navigate to any location *not* in the middle of a function.  We don't want
  to duplicate that function's data in our survey.
* close `whisper_cpp_rva23`.  There is no need to exit Ghidra itself.
* remove all `.txt`, `*log`, and `*.c` files in `/tmp`
* reopen `whisper_cpp_rva23` and navigate to `File⇒Export Program`, then export the entire program as `C/C++` to
  `/tmp/whisper_cpp_rva23.c`
* examine the raw files left in `/tmp`

You should see something like:

```console
/tmp$ ls -lt *.log *.txt *.c
-rw-r-----. 1   1308974 Dec 23 08:14 ghidraRiscvLogger_609884.log
-rw-r-----. 1   1704176 Dec 23 08:14 ghidraRiscvLogger_609903.log
-rw-r-----. 1   1796039 Dec 23 08:14 ghidraRiscvLogger_609893.log
-rw-r-----. 1   6582477 Dec 23 08:14 whisper_cpp_rva23.c
-rw-r-----. 1    563166 Dec 23 08:14 ghidraRiscvLogger_609897.log
-rw-r-----. 1    897604 Dec 23 08:14 ghidraRiscvLogger_609901.log
-rw-r-----. 1   1664068 Dec 23 08:14 ghidraRiscvLogger_609891.log
-rw-r-----. 1    110517 Dec 23 08:14 riscv_summaries_609891.txt
-rw-r-----. 1       780 Dec 23 08:14 ghidraRiscvLogger_609899.log
-rw-r-----. 1       223 Dec 23 08:14 riscv_summaries_609899.txt
-rw-r-----. 1     59232 Dec 23 08:14 riscv_summaries_609901.txt
-rw-r-----. 1     17390 Dec 23 08:14 riscv_summaries_609897.txt
-rw-r-----. 1   1277873 Dec 23 08:14 ghidraRiscvLogger_609886.log
-rw-r-----. 1     81228 Dec 23 08:14 riscv_summaries_609886.txt
-rw-r-----. 1   1771553 Dec 23 08:14 ghidraRiscvLogger_609888.log
-rw-r-----. 1    134163 Dec 23 08:14 riscv_summaries_609888.txt
-rw-r-----. 1    102357 Dec 23 08:14 riscv_summaries_609903.txt
-rw-r-----. 1    101105 Dec 23 08:14 riscv_summaries_609893.txt
-rw-r-----. 1   1639817 Dec 23 08:14 ghidraRiscvLogger_609895.log
-rw-r-----. 1    128292 Dec 23 08:14 riscv_summaries_609895.txt
-rw-r-----. 1     91122 Dec 23 08:14 riscv_summaries_609884.txt
-rw-r-----. 1         0 Dec 23 08:12 ghidraPluginManager.log
```

Sanity check the results:
* `ghidraPluginManager.log` shows zero load errors
* `whisper_cpp_rva23.c` was successfully generated
* The full-program decompilation process was distributed over 10 decompiler spawned PIDs.
  Each PID writes its own log and survey files

Collect and count vector signature lines:

```console
$ cat riscv_summaries_*.txt > riscv_summaries.txt
$ grep 'Vector instructions' riscv_summaries.txt|sort|uniq -c|sort -nr -k1,1 > survey.txt
```

## Examination of raw survey

The survey collects and displays recognized pcode ops following the loop, whether or not they are
semantically linked to the loop.  The most frequent stanza variations are therefore `vector_memcpy`
instances followed by unrelated pcode ops.

```text
451 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | ?,
195 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | +, ?,
105 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | +, +, ?,
 48 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | !=, ?,
 41 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m, | | *, +, +, ?,
 31 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | *, +, ?,
 25 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m, | | *, +, +, <, ?,
 24 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmseq_vi, vfirst_m, | vmsne_vv, vmor_mm, | +, +, ?,
 13 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | +, !=, ?,
  9 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | <, ?,
  8 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | vsetivli_e64m1tama, , ?,
  6 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | ==, ?,
  6 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | +, +, +, !=, ?,
  5 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m, | | ?,
  5 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m, | | +, ?,
  4 Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf4tama, vse32_v, | +, +, !=, ?,
  4 Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf4tama, vlseg2e32_v, vse32_v, | +, ?,
  4 Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf2tama, vse16_v, | +, +, !=, ?,
  4 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, | vsetvli_e8mf4tama, vle32_v, vrgatherei16_vv, vsetvli_e32m1tama, vse32_v, | ?,
  4 Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8_v, vse8_v, | | +, +, <=, ?,
```

Let's filter `vector_memcpy` loop stanzas out of the survey:

```console
/tmp$ grep -v 'vsetvli_e8m1tama, vle8_v, vse8_v, | |' survey.txt|head -20
41 	Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m, | | *, +, +, ?,
25 	Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m, | | *, +, +, <, ?,
24 	Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vle8ff_v, vmseq_vi, vfirst_m, | vmsne_vv, vmor_mm, | +, +, ?,
 5 	Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m, | | ?,
 5 	Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m, | | +, ?,
 4 	Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf4tama, vse32_v, | +, +, !=, ?,
 4 	Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf4tama, vlseg2e32_v, vse32_v, | +, ?,
 4 	Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf2tama, vse16_v, | +, +, !=, ?,
 4 	Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, | vsetvli_e8mf4tama, vle32_v, vrgatherei16_vv, vsetvli_e32m1tama, vse32_v, | ?,
 4 	Vector instructions (handled | unhandled | epilog): | vsetvli_e64m2tama, vlseg2e32_v, vsext_vf2, vsetvli_e8mf4tama, vsuxei64_v, | ?,
 4 	Vector instructions (handled | unhandled | epilog): | vsetvli_e32m1tuma, vle32_v, vfmax_vv, | vsetvli_e32m1tama, , vfmv_sf, , vfredmax_vs, , vfmv_fs, , ?,
 4 	Vector instructions (handled | unhandled | epilog): | vsetvli_e32m1tuma, vle32_v, vfmacc_vv, | <, ?,
 4 	Vector instructions (handled | unhandled | epilog): | vsetvli_e32m1tama, vle32_v, vle32_v, vfmadd_vv, vse32_v, | +, +, +, !=, ?,
 4 	Vector instructions (handled | unhandled | epilog): | vsetvli_e32m1tama, vle32_v, vfmul_vv, vse32_v, | ?,
 4 	Vector instructions (handled | unhandled | epilog): | vsetvli_e32m1tama, vle32_v, vfmul_vv, vse32_v, | *, +, ?,
 3 	Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf4tama, vse32_v, | ?,
 3 	Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf4tama, vse32_v, | +, ?,
 3 	Vector instructions (handled | unhandled | epilog): | vsetvli_e8mf4tama, vle32_v, vse32_v, | ?,
 3 	Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m, | | *, +, +, +, ?,
 3 	Vector instructions (handled | unhandled | epilog): | vsetvli_e32m1tuma, vle32_v, vfmax_vv, | *, ?,
```

Inspection suggests:

* `vector_strlen` and its variants are common, with vector instruction sequences of `vsetvli_e8m1tama, vle8ff_v, vmseq_vi, vfirst_m`.  But not all
  loop epilogs have the same operations in the same order.
* `vector_strcmp` and its variants are also common, with vector instruction sequences including two instances of `vle8ff_v`.
* vector reduction loops and multiply-accumulate loops are likely to have `tail unchanged` semantics rather than `tail agnostic` semantics.  This
  means affected vector operations will be read-modify-write on their output vector register.  That in turn means their user pcode needs to be rewritten
  to include the output register as an additional input register.
* the survey occasionally shows ' ' as an epilog operation.  That is a coding error easily addressed.
* there are at least four instances of `LMUL > 1` and `vlseg*` instructions.  This *might* be a case where vector registers are grouped.  In this case it is more
  likely to be some sort of widening operation that does not modify vector registers other than the ones named as output registers.  More study is needed here.
