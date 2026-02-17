---
title: Walkthrough Examples
description: An early version of the plugin recognizes the RISC-V inline vectorization of `memcpy`
weight: 50
---

What does an early version of the RISC-V vector plugin actually do for us?  What more do we want it to do?  This page walks through
a couple of examples:

* The first is a synthetic collection of memcpy assembly routines in `test/memcpy_exemplars.S`.  This includes four fixed-length memcpy
  functions and one variable-length memcpy looping function.
* The second is a full `whisper-cpp` build using gcc 15 for RISC-V and a 64 bit rva23 machine architecture.  This is a complex example
  where the transforms need some work.

## memcpy_exemplars

The ghidra listing view shows us:

```text
**************************************************************
*                          FUNCTION                          *
**************************************************************
undefined memcpy_i2()
    vsetivli                       zero,0x2,e8,mf8,ta,ma 
    vle8.v                         v1,(a1)
    vse8.v                         v1,(a0)
    ret
```

The decompiler window shows this loop-free pattern has been transformed:

```c
void memcpy_i2(undefined8 param_1,undefined8 param_2)
{
  vector_memcpy((void *)param_1,(void *)param_2,2);
  return;
}
```

The functions `memcpy_i4`, `memcpy_i8`, `memcpy_i15` show similar transforms,
recognizing the pattern even when unrelated instructions are interleaved
with the vector instructions.

The function `memcpy_v1` is more complex, since it involves a size parameter
rather than a size known at compile time.  Therefore a loop is present.

The Ghidra assembly view of `memcpy_v1` - after manually adjusting the function signature - is:

```text
**************************************************************
*                          FUNCTION                          *
**************************************************************
void  __stdcall memcpy_v1(void * dest, void * src, longlong size)
  a0:8           <RETURN>
  a0:8           dest
  a1:8           src
  a2:8           size
memcpy_v1                                       XREF[1]:     0010005a(j)  
    vsetvli                        a3,size,e8,m1,ta,ma  
    vle8.v                         v1,(src)
    c.sub                          size,a3
    c.add                          dest,a3
    vse8.v                         v1,(dest)
    c.add                          src,a3
    c.bnez                         size,memcpy_v1
    ret
```
The decompiler view shows

```c
void * memcpy_v1(void *dest,void *src,int size)
{
void memcpy_v1(void *dest,void *src,longlong size)

{
  do {
    vector_memcpy((void *)dest,(void *)src,size);
  } while ;
  return;
}
}
```

An earlier version of the plugin used the existing `builtin_memcpy` function.  That would be a problem here,
since `builtin_memcpy` follows the `memcpy` convention of returning the destination pointer in register `a0`.
The vector instruction sequence doesn't satisfy that convention, so we need a new user-defined builtin with a `void` return.
That's easy enough to add since our plugin manager has hooked the lookup function for data typed builtin functions.

## whisper-cpp

>Note: this section will change rapidly as issues surface and the transforms evolve

>Note: If a large function decompilation times out repeatedly, you may have the logging subsystem dumping
>      too much information.  Try setting the SPDLOG level to `info` or `warn` in `riscv_c::plugin_init`.

Open `whisper_cpp_rva23` and export the entire program as a C/C++ source file.  That will force a decompilation run
on all functions.

First collect some overall statistics:

|Parameter | Value |
| -------- | ----: |
| bytes | 1956494 |
| instructions | 275351 |
| vsetvli instructions | 4119 |
| vsetivli instructions | 1430 |
| vector_memset transforms | 195 |
| vector_memcpy transforms | 178 |
| functions | 1914 |
| decompiler exceptions | 137 |

First impressions:

* Loop-free matching for `vector_memset` and `vector_memcpy` patterns appears to be working.
* Loop matching patterns appear to be failing everywhere, often with a warning like `Loop analysis failed with 27 descendents`.
* There are many more Phi node pcodeops attached to the vsetvli instructions than found in the simplistic memcpy_exemplars test case

One pattern will need some extra design effort:

```c
do {
  lVar34 = vsetvli_e8m1tama(lVar16);
  auVar49 = vle8_v(puVar4);
  lVar16 = lVar16 - lVar34;
  puVar4 = puVar4 + lVar34;
  vse8_v(auVar49,puVar26);
  puVar26 = puVar26 + lVar34;
} while (lVar16 != 0);
local_6a4 = iVar9;
lVar16 = whisper_init_from_file_with_params(whisper_params._192_8_,puVar26);
```

The `puVar26` variable is a loop temporary, but it is interpreted as a possible second parameter to `whisper_init_from_file_with_params`.

We clearly have a problem with Phi nodes and dependency calculations. And we need more loop test cases with non-trivial control flows.
Try exporting a smallish example of a vector loop and reload it as raw.  The decompiler plugin shows an unexpected opcode of `CPUI_PTRADD` (65).
Perhaps we should add this as an expected arithmetic op.

### New test case

Select the whisper function `string * __thiscall std::string::string<>(string *this,char *param_1,allocator *param_2)` at 0x209be as our test case,
saving it to xml and converting it into `test/whisper_sample_1_save.xml` and `test/whisper_sample_1.ghidra`.  This sample includes two `vsetvli` loops,
of which the second is a memcpy loop.  The control flow is relatively simple.

The listing for the block we want to transform is:

```as
LAB_00020a3e                                    XREF[1]:        00020a50(j)  
    vsetvli                        a3,param_2,e8,m1,ta,ma  
    vle8.v                         v1,(param_1)
    c.sub                          param_2,a3
    c.add                          param_1,a3
    vse8.v                         v1,(this)
    c.add                          this,a3
    c.bnez                         param_2,LAB_00020a3e
    c.j                            LAB_000209fe
```

The `print raw` listing includes:

```text
Basic Block 9 0x00020a3e-0x00020a50
0x00020a3e:a4:	a2(0x00020a3e:a4) = u0x10000019(0x00020a50:e2) ? u0x10000049(0x000209f2:e8) ? u0x10000049(0x000209f2:e8)
0x00020a3e:9f:	a1(0x00020a3e:9f) = a1(0x00020a48:47) ? a1(i) ? a1(i)
0x00020a3e:9a:	a0(0x00020a3e:9a) = a0(0x00020a4e:f4) ? a0(0x000209c8:ea) ? a0(0x00020a28:ed)
0x00020a3e:43:	a3(0x00020a3e:43) = vsetvli_e8m1tama(a2(0x00020a3e:a4))
0x00020a42:45:	v1(0x00020a42:45) = vle8_v(a1(0x00020a3e:9f))
0x00020a46:cb:	u0x10000008(0x00020a46:cb) = - a3(0x00020a3e:43)
0x00020a46:46:	a2(0x00020a46:46) = a2(0x00020a3e:a4) + u0x10000008(0x00020a46:cb)(*#0x1)
0x00020a48:47:	a1(0x00020a48:47) = a1(0x00020a3e:9f) + a3(0x00020a3e:43)(*#0x1)
0x00020a4a:49:	vse8_v(v1(0x00020a42:45),a0(0x00020a3e:9a))
0x00020a4e:f3:	u0x100000a1(0x00020a4e:f3) = (cast) a0(0x00020a3e:9a)
0x00020a4e:4a:	u0x100000a9(0x00020a4e:4a) = u0x100000a1(0x00020a4e:f3) + a3(0x00020a3e:43)
0x00020a4e:f4:	a0(0x00020a4e:f4) = (cast) u0x100000a9(0x00020a4e:4a)
0x00020a50:4b:	u0x00018500:1(0x00020a50:4b) = a2(0x00020a46:46) != #0x0
0x00020a50:e2:	u0x10000019(0x00020a50:e2) = a2(0x00020a46:46)
0x00020a50:4c:	goto r0x00020a3e:1(free) if (u0x00018500:1(0x00020a50:4b) != 0)

Basic Block 10 0x000209fe-0x00020a0e
0x000209fe:9b:	a0(0x000209fe:9b) = a0(0x000209c8:ea) ? a0(0x000209c8:ea) ? a0(0x00020a4e:f4)
0x000209fe:31:	a3(0x000209fe:31) = *(ram,a0(i))
0x00020a00:f5:	u0x100000b1(0x00020a00:f5) = (cast) a0(i)
0x00020a00:33:	u0x100000b9(0x00020a00:33) = u0x100000b1(0x00020a00:f5) + #0x8
0x00020a00:f6:	u0x00019180(0x00020a00:f6) = (cast) u0x100000b9(0x00020a00:33)
0x00020a00:34:	*(ram,u0x00019180(0x00020a00:f6)) = a5(0x000209ee:24)
0x00020a02:35:	a5(0x00020a02:35) = a5(0x000209ee:24) + a3(0x000209fe:31)(*#0x1)
0x00020a04:38:	*(ram,a5(0x00020a02:35)) = #0x0:1
0x00020a0e:41:	return(#0x0) a0(0x000209fe:9b)
```

The three-argument Phi nodes at 0x20a3e are new - the existing transform only handles two argument nodes.

The root problem appears to be the use of `a0` in our memcpy loop in a function with a `void` return.
This expands the number of dependencies into pcodes we can't simply delete.

What design makes sense here?

* registers a0, a1, a2, and a3 are modified in the loop
* register a2 is known to be zero on exit.
* registers a0, a1, and a3 have values dependent on the vector register length, so
  should have no dependencies outside of the loop

At a minimum we likely want to identify any temporary registers used within a vector loop, then find any
Phi node descendants of those registers outside the loop, then use `data.opUnsetInput(...)` to remove those
varnode references.

We also need to document these three-input Phi nodes, understanding why we get duplicated entries and whether
the loop varnode always appears in the first slot.

Let's establish a basic integration test first, since a significant restructuring of the matching code looks likely.

Workflow:

1. applyOp triggers on the pcode op at `0x00020a3e:43`
    * get the current blockId with `getParent`.
    * get any pcodes at the same address using `data.beginOp(vsetOp->getAddr())`, building Phi node structures
2. collect descendants of `0x00020a3e:43`, recursively for any pcodes within the current block (or possibly the range from vset to end of block)
   but not for any pcodes outside of it.  The interior pcodes are candidates to be absorbed, while the exterior pcodes are candidates for varnode erasure.

Restructure the `vector_loop_match` code to provide a clear separation between pcodeops inside and outside the vector loop, and to purge varnode references
to deleted pcodeops.Rerun the integration test:

```console
ghidra_decompiler_plugins$ ./integrationTest.py 
INFO:root:Cleaning the executable directory /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/
INFO:root:Running rm -f /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest
INFO:root:Running bazel build -c opt @ghidra//:decompile
INFO:root:Running bazel build -c dbg @ghidra//:decompile_datatest
.INFO:root:Removing any previous plugin
INFO:root:Running rm -f /tmp/libriscv_vector.so
INFO:root:Building and installing the plugin
INFO:root:Running bazel build -c dbg plugins:riscv_vector
.INFO:root:Running SLEIGHHOME=/opt/ghidra_11.4_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so valgrind /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/memcpy_exemplars.ghidra
.INFO:root:Running SLEIGHHOME=/opt/ghidra_11.4_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so valgrind /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_sample_1.ghidra with output to /tmp/whisper_sample_1.testlog
.
----------------------------------------------------------------------
Ran 4 tests in 19.371s

OK
```

A manual inspection of `/tmp/whisper_sample_1.testlog` shows the vector_memcpy transform has been made.  Compare this with a control run without `DECOMP_PLUGIN` set to see if there is any
obvious corruption of the decompilation.  That looks good.  Also note that this test function includes another vector stanza we will end up calling `vector_strlen`.

Now restart Ghidra with the new plugin, and collect statistics to measure our progress:

|Parameter | Value | Notes |
| -------- | ----: | ----- |
| bytes | 1956494 | unchanged |
| instructions | 275351 | unchanged |
| vsetvli instructions | 4119 | unchanged |
| vsetivli instructions | 1430 | unchanged |
| vector_memset transforms | 124 | was 195 |
| vector_memcpy transforms | 191 | was 178 |
| functions | 1914 |  unchanged |
| decompiler exceptions | 18 | was 137 |

So we found more `vector_memcpy` transforms, presumably those in loops, but fewer `vector_memset` transforms.
The decrease in `vector_memset` transforms is a surprise to be investigated.
The big improvement was in fewer decompiler exceptions.  The logfile shows quite a few warnings to be investigated too.

The plugin found transforms of only a small percentage of the vector stanzas, so there is quite a bit of work left to do.

One of the functions that generated a decompiler exception was the `main` function, arguably the most important function
to be evaluated in Ghidra.  Let's turn that large function into a new test case and see why the exceptions are being thrown.
The most likely cause is a failure to handle dependencies of pcodeops removed during a transform.

### Whisper-cpp Main function test case

Not every vector instruction sequence is worth understanding - and the effort it takes to
transform it into something more human-readable.  Sequences that occur in the `main` function
are likely to be more important to the Ghidra user than vector sequences that occur in a vector
dot product function.  Our workflow constructs vector sequence transforms only as needed,
prioritizing sequences with a clear transform representation and sequences that occur at
higher levels of the binary to be analyzed.

>Note: other workflows could be very different.  For example, an executable built *explicitly*
>      for a vector length of 256 bits could fail on a hardware thread limited to 128 bits.

Use Ghidra to locate the `main` function within whisper-cpp and export its 8 memory segments
into a new Ghidra datatest save file `test/whisper_main_save.xml`.  Next add a datatest script
as `test/whisper_main.ghidra`.

Exercise this datatest without a plugin as a control run without valgrind:

```console
$ SLEIGHHOME=/opt/ghidra_11.4_DEV/ /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_main.ghidra
```

Repeat with the plugin active

```console
$ SLEIGHHOME=/opt/ghidra_11.4_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_main.ghidra > /tmp/decomp_main.log
$ cat /tmp/decomp_main.log
[decomp]> restore test/whisper_main_save.xml
test/whisper_main_save.xml successfully loaded: RISC-V 64 little general purpose compressed
[decomp]> map function 0x20fd0 main
[decomp]> parse line extern int main(int argc, char** argv);
[decomp]> load function main
Function main: 0x00020fd0
[decomp]> decompile main
Decompiling main
Low-level ERROR: Free varnode has multiple descendants
Unable to proceed with function: main
[decomp]> print C
Execution error: No function selected
[decomp]> print raw
Execution error: No function selected
[decomp]> 
```

Examine the logs to decide on next steps:

* The plugin completed processing in spite of the low level error thrown.  This suggests
  that the free varnode descendant rule is only applied after all `apply` calls in a given
  Rule or group of rules.  That means we can't immediately localize the vector stanza that
  caused the error.
* The messaging between `ghidraRiscvLogger.log` and `ghidraPluginAnalysis.log` needs work:
    * We need an explicit `info` level log message when the plugin exits
    * The two logs should display a clear demarcation and correlation tag on each new
      vector stanza entered.
    * Explore the possibility of merging the two logs with a `printRaw` to a
      `std::stringstream`.
* Add a new `TRANSFORM_LIMIT` field to the plugin to skip processing further vector
  stanzas after a fixed number of executed transforms.  This should allow bisection
  analysis of large functions like `main`.

Add the transform limit and bisect to find the first 6 transforms complete without an error
thrown, all of which are loop-free.  Repeat with the limit bumped to 7 transforms.
The log file shows:

```console
$ grep -E 'Inserting|Transforming|Analyzing' ghidraRiscvLogger.log
[2025-05-05 08:26:17.464] [riscv_vector] [info] Inserting vector op 0x11000001 at 0x210c8
[2025-05-05 08:26:17.464] [riscv_vector] [info] Inserting vector op 0x11000001 at 0x210d4
[2025-05-05 08:26:17.464] [riscv_vector] [info] Inserting vector op 0x11000001 at 0x210e8
[2025-05-05 08:26:17.464] [riscv_vector] [info] Inserting vector op 0x11000000 at 0x210b4
[2025-05-05 08:26:17.465] [riscv_vector] [info] Inserting vector op 0x11000000 at 0x211d8
[2025-05-05 08:26:17.465] [riscv_vector] [info] Inserting vector op 0x11000001 at 0x2130a
[2025-05-05 08:26:17.465] [vector_loop] [trace] Analyzing potential vector loop at 0x21454
[2025-05-05 08:26:17.466] [vector_loop] [trace] Analyzing potential vector loop at 0x21552
[2025-05-05 08:26:17.472] [vector_loop] [trace] Analyzing potential vector loop at 0x21b64
[2025-05-05 08:26:17.472] [vector_loop] [info] Transforming selection into vector_memcpy
```

the transforms at 0x21454, 0x21552, and 0x21b64 should have succeeded.
* 0x21454 analysis found 34 descendants, aborting the transform
* 0x21552 analysis found 186 descendants, aborting the transform
* 0x21b64 analysis found 12 in-loop descendants and 3 external descendants
    * the log shows an anomaly `Pcode to be trimmed has 6 inputs at address 0x21b7a`

```text
PcodeOp: a0(0x00021b7a:a00) = call ffunc_0x000cab18(free)(s2(0x000214c6:361e),a3(0x00021b5c:9f0),a4(0x00021b46:9e0),a6(0x00021b74:9fb),a7(0x00021b6e:9f8));      OpName: call;   Addr: 0x21b7a
```

Therefore we need a better way to handle descendants appearing in CALL pcodes.
The offending vector stanza looks like this:

```text
                     LAB_00021b64                                    XREF[1]:        00021b76(j)  
00021b64 d7 77 05 0c     vsetvli                        a5,a0,e8,m1,ta,ma  
00021b68 87 80 08 02     vle8.v                         v1,(a7)
00021b6c 1d 8d           c.sub                          a0,a5
00021b6e be 98           c.add                          a7,a5
00021b70 a7 00 08 02     vse8.v                         v1,(a6)
00021b74 3e 98           c.add                          a6,a5
00021b76 7d f5           c.bnez                         a0,LAB_00021b64
00021b78 4a 85           c.mv                           a0,s2
                     try { // try from 00021b7a to 00021b7d has its CatchHandler @
00021b7a ef 80 fa 79     jal                            ra,SUB_000cab18
                     } // end try from 00021b7a to 00021b7d
```

registers a6 and a7 are valid parameter registers, but without committing the
signature for SUB_000cab18 Ghidra guesses dependencies incorrectly.  This *may* be a case
of a transform only succeeding after called function signatures are correctly
committed.

In any event, the immediate fix is to terminate dependency searches whenever a CALL
pcodeop appears as a dependency.  Preventing decompiler exceptions is the most important
goal.

Install a quick fix and continue increasing TRANSFORM_LIMIT until we get 13 stable transforms and fail
on the 14th at 0x23866.

The next problem was a bad assumption about Phi or MULTILEVEL nodes.  These are used to trace dependencies
at branch points, giving all potential histories for each register or memory address touched in a block or loop.
In a `vector_memcpy` loop these nodes connect internal loop varnodes with external varnodes.  The loop transforms
erase the internal loop varnodes, so we need to generate `vector_memcpy` calls using varnodes external to the loop.
The current code now does a better job of identifying external varnodes, so that only the internal varnodes are
erased.  Some Phi nodes involve three varnode references - one internal and two external, without clearly identifying
which single varnode should be used in the transform.  The current code picks one randomly, while a better approach would
generate a new Phi node connecting the two external varnodes to a temporary varnode used in the `vector_memcpy` call.

Repeat the full scan of `whisper-cpp`:

|Parameter | Value | Notes |
| -------- | ----: | ----- |
| bytes | 1956494 | unchanged |
| instructions | 275351 | unchanged |
| vsetvli instructions | 4119 | unchanged |
| vsetivli instructions | 1430 | unchanged |
| vector_memset transforms | 410 | was 124 |
| vector_memcpy transforms | 883 | was 191 |
| functions | 1914 |  unchanged |
| decompiler exceptions | 15 | was 18 |

The functions driving exceptions are:

```text
$ grep 'Decompiler process died' whisper_cpp_rva23.c
Cause: Exception while decompiling 00030728: Decompiler process died
Cause: Exception while decompiling 000307bc: Decompiler process died
Cause: Exception while decompiling 0006d5ec: Decompiler process died
Cause: Exception while decompiling 0007c78e: Decompiler process died
Cause: Exception while decompiling 0007c8b2: Decompiler process died
Cause: Exception while decompiling 00081d24: Decompiler process died
Cause: Exception while decompiling 00090296: Decompiler process died
Cause: Exception while decompiling 0009bd22: Decompiler process died
Cause: Exception while decompiling 0009d7d0: Decompiler process died
Cause: Exception while decompiling 0009f3de: Decompiler process died
Cause: Exception while decompiling 000a0c9a: Decompiler process died
Cause: Exception while decompiling 000b3824: Decompiler process died
Cause: Exception while decompiling 000b97c0: Decompiler process died
Cause: Exception while decompiling 000d7a72: Decompiler process died
Cause: Exception while decompiling 000e9ef2: Decompiler process died
```

Add the `min` function to our integration tests and take a look at the functions where the decompiler process died.

Some of these functions decompile in the Ghidra GUI after export.  That's probably due to the TRANSFORM_LIMIT being
hit earlier.  Functions like 0x00030728 appear to be failing because more complex vector stanzas are being mis-identified
as simple stanzas, leaving dependencies stranded after transform.

### Whisper-cpp false match test case

Turn the function at 0x030728 (`drwav_u8_to_s32`) into a test case where we apparently get a false match to vector_memcpy folowed
by a decompiler exception.

The relevant assembly code is:

```as
        LAB_00030750               XREF[1]:        00030744(j)
00030750    li        a4,-0x80
00030754    vsetvli   a5,zero,e8,mf4,ta,ma
00030758    vmv.v.x   v3,a4
        LAB_0003075c               XREF[1]:        00030780(j)
0003075c    vsetvli   a5,a2,e8,mf4,ta,ma
00030760    vle8.v    v2,(a1)
00030764    c.sub     a2,a5
00030766    c.add     a1,a5
00030768    vadd.vv   v2,v2,v3
0003076c    vsetvli   zero,zero,e32,m1,ta,ma
00030770    vsext.vf4 v1,v2
00030774    vsll.vi   v1,v1,0x18
00030778    vse32.v   v1,(a0)
0003077c    sh2add    a0,a5,a0
00030780    c.bnez    a2,LAB_0003075c
```

The original C source code is:

```c
DRWAV_API void drwav_u8_to_s32(drwav_int32* pOut, const drwav_uint8* pIn, size_t sampleCount)
{
    size_t i;
    if (pOut == NULL || pIn == NULL) {
        return;
    }
    for (i = 0; i < sampleCount; ++i) {
        *pOut++ = ((int)pIn[i] - 128) << 24;
    }
}
```

At first glance this looks like a vector_memcpy stanza with some extra vector ops.

Clarify a few tests and try again

|Parameter | Value | Notes |
| -------- | ----: | ----- |
| bytes | 1956494 | unchanged |
| instructions | 275351 | unchanged |
| vsetvli instructions | 4119 | unchanged |
| vsetivli instructions | 1430 | unchanged |
| vector_memset transforms | 416 | was 410 |
| vector_memcpy transforms | 885 | was 883 |
| functions | 1914 |  unchanged |
| decompiler exceptions | 5 | was 15 |

The first of the remaining exceptions appears to be another bug in the analysis loop - there are other vector instructions present in the loop
at 0x9bdd8.  It almost looks like vector registers are not collecting dependencies.  Perhaps the problem is with the SLEIGH pcode generated for
`vfmadd.vv  v1, v2, v31`, where register v1 is used for both input and output.  The current SLEIGH definition is:

```text
vd=vfmadd_vv(vs1,vs2);
```

A better definition would be

```text
vd=vfmadd_vv(vs1,vs2,vd);
```

Install that and some similar changes then rebuild Ghidra and try again.

|Parameter | Value | Notes |
| -------- | ----: | ----- |
| vector_memcpy transforms | 894 | was 885 |
| decompiler exceptions | 2 | was 5 |

The two remaining exceptions are in 000b3824 (`whisper_model_load`) and 000b97c0 (`whisper_wrap_segment`).  Turn these
into two more regression tests `whisper_sample_4` and `whisper_sample_5` respectively.

`whisper_sample_4` shows an anomaly - the datatest throws an assertion error whether or not
a plugin is used.  There is likely something wrong with how the datatest is structured.
The assertion error occurs within `ghidra::Heritage::splitByRefinement`at (heritage.cc:1748).
Defer this until we get `whisper_sample_5` passing, adding a skipped test to `integrationTest.py`.

Step through `whisper_sample_5` bisecting with `TRANSFORM_LIMIT` to show a problem on the 7th transform
around 0x9bd50.  The log file shows:

```text
In Loop PcodeOp: a4(0x000b9d50:4fb) = vsetvli_e8m1tama(a0(0x000b9d50:d60));     OpName: syscall;        Addr: 0xb9d50
In Loop PcodeOp: s1(0x000b9d50:d31) = s1(0x000b9d5a:4ff) ? s1(0x000b9c7c:487) ? s1(0x000b9c7c:487);     OpName: ?;      Addr: 0xb9d50
In Loop PcodeOp: a0(0x000b9d50:d60) = a0(0x000b9d58:4fe) ? s2(0x000b9c94:496) ? s2(0x000b9c94:496);     OpName: ?;      Addr: 0xb9d50
In Loop PcodeOp: a6(0x000b9d50:fcd) = a6(0x000b9d60:502) ? a5(0x000b9d48:4f8) ? s10(0x000b9cfa:106e);   OpName: ?;      Addr: 0xb9d50
In Loop PcodeOp: a5(0x000b9d50:2017) = a5(0x000b9d50:2017) ? a5(0x000b9d48:4f8) ? s10(0x000b9cfa:106e); OpName: ?;      Addr: 0xb9d50
In Loop PcodeOp: v1(0x000b9d54:4fd) = vle8_v(s1(0x000b9d50:d31));       OpName: syscall;        Addr: 0xb9d54
In Loop PcodeOp: a0(0x000b9d58:4fe) = a0(0x000b9d50:d60) + u0x100000c0(0x000b9d58:11e3);        OpName: +;      Addr: 0xb9d58
In Loop PcodeOp: u0x100000c0(0x000b9d58:11e3) = a4(0x000b9d50:4fb) * #0xffffffffffffffff;       OpName: *;      Addr: 0xb9d58
In Loop PcodeOp: s1(0x000b9d5a:4ff) = s1(0x000b9d50:d31) + a4(0x000b9d50:4fb);  OpName: +;      Addr: 0xb9d5a
In Loop PcodeOp: vse8_v(v1(0x000b9d54:4fd),a6(0x000b9d50:fcd)); OpName: syscall;        Addr: 0xb9d5c
In Loop PcodeOp: a6(0x000b9d60:502) = a6(0x000b9d50:fcd) + a4(0x000b9d50:4fb);  OpName: +;      Addr: 0xb9d60
In Loop PcodeOp: u0x00018500:1(0x000b9d62:503) = a0(0x000b9d58:4fe) != #0x0;    OpName: !=;     Addr: 0xb9d62
In Loop PcodeOp: goto r0x000b9d50:1(free) if (u0x00018500:1(0x000b9d62:503) != 0);      OpName: goto;   Addr: 0xb9d62
Out of Loop PcodeOp: s2(0x000b9d64:505) = s2(0x000b9c94:496) + a5(0x000b9d50:2017);     OpName: +;      Addr: 0xb9d64
Out of Loop PcodeOp: *(ram,u0x00010d80(0x000b9d92:526)) = s2(0x000b9d64:505);   OpName: store;  Addr: 0xb9d92
...
Pcode to be trimmed PcodeOp: s2(0x000b9d64:505) = s2(0x000b9c94:496) + a5(0x000b9d50:2017);     OpName: +;      Addr: 0xb9d64
Pcode after trimming PcodeOp: s2(0x000b9d64:505) = s2(0x000b9c94:496) + <null>; OpName: +;      Addr: 0xb9d64
```

The disassembly includes:

```as
LAB_000b9d4c                                    XREF[1]:        000ba45c(j)  
    c.mv                           a6,a5
    c.mv                           param_1,s2
LAB_000b9d50                                    XREF[1]:        000b9d62(j)  
    vsetvli                        a4,param_1,e8,m1,ta,ma  
    vle8.v                         v1,(s1)
    c.sub                          param_1,a4
    c.add                          s1,a4
    vse8.v                         v1,(a6)
    c.add                          a6,a4
    c.bnez                         param_1,LAB_000b9d50
```

The Phi nodes look like the culprit here
* `a5(0x000b9d50:2017)` should not be deleted and should have its descendants followed.  This Phi node is not affected by the loop.
* `a6(0x000b9d50:fcd)` is a three argument Phi node without duplicates.  It should probably be replaced with two argument Phi node

It's not clear how to properly transform this vector_memcpy loop, so let's just try to minimize exceptions by failing the transform
match if Phi registers don't match or if four or more Phi nodes are associated with the `vsetvli` instruction location.

Scan the entire whisper-cpp binary for results:

|Parameter | Value | Notes |
| -------- | ----: | ----- |
| bytes | 1956494 | unchanged |
| instructions | 275351 | unchanged |
| vsetvli instructions | 4119 | unchanged |
| vsetivli instructions | 1430 | unchanged |
| vector_memset transforms | 419 | was 416 |
| vector_memcpy transforms | 904 | was 885 |
| functions | 1914 |  unchanged |
| decompiler exceptions | 1 | was 5 |

### Next steps

1. Explore the exception thrown by the `whisper_sample_4` test, even in the absence of a plugin.  Is this due to the unusual size of the
   datatest, some sort of version skew between the current tip of Ghidra and the released version, an anomalous vector instruction
   used within the sample, or something else?  Opening the `whisper_model_load` function in the Ghidra GUI without a plugin shows
   about 86 vector stanzas similar to `vector_memcpy` but with anomalous instructions included in the loop.  This may be a Ghidra decompiler
   bug to watch out for.
     ```c
     do {
       lVar55 = vsetvli_e8m1tama(lVar53);
       auVar57 = vle8_v(psVar26);
       lVar53 = lVar53 - lVar55;
       psVar26 = psVar26 + lVar55;
       vse8_v(auVar57,psVar31);
       psVar31 = psVar31 + lVar55;
       local_b8 = (string *)local_a8;  // this instruction does not occur within the loop and may indicate an SSA or Heritage bug
     } while (lVar53 != 0);
     ```
2. Work through the other whisper samples to search for missing transforms or falsely-applied transforms.
3. Include integration tests to gather transform counts like `grep -P '^\s+vector_memcpy' /tmp/whisper_main.testlog|wc` to see
   if the number of transforms is as expected.
4. Search for vector builtins worth transforming.  `vector_strlen` is a likely possibility.  How much of the vector loop analyzer would
   be useful for these?

## Survey

We have basic transform code working, but we don't know yet how well it is working or how to improve it.  Let's step through the
samples we have to evaluate quality and to tune up the diagnostic logging.  For this series we will keep `TRANSFORM_LIMIT=INT_MAX`
and `loglevel=spdlog::level::trace`.  Work through the datatests from smallest to largest.

### whisper_sample_1 (string_constructor at 0x209be)

This function has two vector stanzas, a `vector_strlen` stanza needing a transform and a `vector_memcpy` stanza that has a correct transform.
The vector_strlen stanza at 0x209d2 looks like this:

```as
    c.li      a3,0x0
    c.mv      a5,param_1
LAB_000209d2
    vsetvli   param_2,zero,e8,m1,ta,ma
    c.add     a5,a3
    vle8ff.v  v1,(a5)
    vmseq.vi  v1,v1,0x0
    csrrs     a3,vl,zero
    vfirst.m  a6,v1
    blt       a6,zero,LAB_000209d2
    c.add     a5,a6
    c.sub     a5,param_1
```
Notes:
* we would want to translate this to `a5=vector_strlen(param_1)`
* key features are the `zero` passed to `vsetvli`, `vle8ff.v`, and `vfirst.m`
* the code straddles three Blocks
* `param_2` is set but unused
* there is a hidden dependancy where `vl` is an output of `vsetvli`
* the result registar `a5` is passed as an input to `vector_memcpy`, which is
  enough to abort transform analysis due to unbounded dependancies.
* there appear to be 143 instances of this `vector_strlen` pattern in the whisper-cpp executable.

If we want to build transform logic for this, we need to stop collecting
erasable dependancies on `a5` - the second parameter of the `vle8ff.v`
instruction -  after we find the `c.sub` instruction.

### whisper_sample_2 - (drwav_u8_to_s32 at 0x30728)

```as
LAB_00030750:
    li         a4,-0x80
    vsetvli    a5,zero,e8,mf4,ta,ma 
    vmv.v.x    v3,a4

LAB_0003075c:
    vsetvli    a5,a2,e8,mf4,ta,ma 
    vle8.v     v2,(a1)
    c.sub      a2,a5
    c.add      a1,a5
    vadd.vv    v2,v2,v3
    vsetvli    zero,zero,e32,m1,ta,ma 
    vsext.vf4  v1,v2
    vsll.vi    v1,v1,0x18
    vse32.v    v1,(a0)
    sh2add     a0,a5,a0
    c.bnez     a2,LAB_0003075c
```

The decompilation window shows:

```c
vsetvli_e8mf4tama(0);
auVar6 = vmv_v_x(0xffffffffffffff80);
do {
  lVar4 = vsetvli_e8mf4tama(param_3);
  auVar5 = vle8_v(param_2);
  param_3 = param_3 - lVar4;
  param_2 = param_2 + lVar4;
  auVar5 = vadd_vv(auVar5,auVar6);
  vsetvli_e32m1tama(0);
  auVar5 = vsext_vf4(auVar5);
  auVar5 = vsll_vi(auVar5,0x18);
  vse32_v(auVar5,param_1);
  param_1 = param_1 + lVar4 * 4;
} while (param_3 != 0);
```

The original source code is:

```c
DRWAV_API void drwav_u8_to_s32(drwav_int32* pOut, const drwav_uint8* pIn, size_t sampleCount)
{
    size_t i;
    if (pOut == NULL || pIn == NULL) {
        return;
    }
    for (i = 0; i < sampleCount; ++i) {
        *pOut++ = ((int)pIn[i] - 128) << 24;
    }
}
```

The interesting features include:

* multiple `vsetvli` instructions with varying element sizes
* the cast from u8 to s32 supported by the second and third `vsetvli` instructions
* the three explicit vector ops providing addition, sign extension, and logical shift.

We might eventually transform loop stanzas like this into:

```c
  std::transform(pIn.begin(), pIn.end(), pOut.begin(), [](uint8 n){ return ((int)n-2)<< 24;});
```

### whisper_sample_3 - (quantize_row_q8_K_ref at 0x9bd22)

This is a larger function with many vector instructions and no completed transforms.

The source code for the function is:

```c
void quantize_row_q8_K_ref(const float * restrict x, block_q8_K * restrict y, int64_t k) {
    assert(k % QK_K == 0);
    const int64_t nb = k / QK_K;
    for (int i = 0; i < nb; i++) {
        float max = 0;
        float amax = 0;
        for (int j = 0; j < QK_K; ++j) {
            float ax = fabsf(x[j]);
            if (ax > amax) {
                amax = ax; max = x[j];
            }
        }
        if (!amax) {
            y[i].d = 0;
            memset(y[i].qs, 0, QK_K);
            x += QK_K;
            continue;
        }
        //const float iscale = -128.f/max;
        // We need this change for IQ2_XXS, else the AVX implementation becomes very awkward
        const float iscale = -127.f/max;
        for (int j = 0; j < QK_K; ++j) {
            int v = nearest_int(iscale*x[j]);
            y[i].qs[j] = MIN(127, v);
        }
        for (int j = 0; j < QK_K/16; ++j) {
            int sum = 0;
            for (int ii = 0; ii < 16; ++ii) {
                sum += y[i].qs[j*16 + ii];
            }
            y[i].bsums[j] = sum;
        }
        y[i].d = 1/iscale;
        x += QK_K;
    }
}
```

This one is far beyond our abilities to transform.  Key features include:

* loops nested three deep in the source code, two deep in the implementation
* the compiler unrolls at least one loop since it knows something of the
  number of iterations
* the compiler interleaves unrolled operations to minimize memory access latency

### whisper_sample_5 - (whisper_wrap_segment at 0xb97c0)

This function shows some odd behavior.  The following *should* be transformed into
a `vector_memcpy`.

```as
LAB_000ba13a:
    vsetvli  a4,a5,e8,m1,ta,ma  
    vle8.v   v1,(param_4)
    c.sub    a5,a4
    c.add    param_4,a4
    vse8.v   v1,(param_2)
    c.add    param_2,a4
    c.bnez   a5,LAB_000ba13a
```

Instead the decompiler gives:

```c
do {
  lVar6 = vsetvli_e8m1tama(pbVar20);
  auVar36 = vle8_v(pbVar7);
  pbVar20 = pbVar20 + -lVar6;
  pbVar7 = pbVar7 + lVar6;
  vse8_v(auVar36,ppbVar12);
  ppbVar12 = (byte **)((long)ppbVar12 + lVar6);
  ppbVar3 = ppbVar8;
} while (pbVar20 != (byte *)0x0);
```

The `ppbVar3 = ppbVar8` line makes little sense, as there are no corresponding instructions in the loop.
Perhaps this is the decompiler preserving a register value in case it is needed for a subsequent CALL instruction?
This same behavior appears when no transform plugin is active, so it is apparently something found in
an unmodified decompiler.  Examining the `print raw` output for this function gives us some hints:

* there are about 30 Phi nodes bound to `000ba13a`, some with 5 varnode slots
LAB_000ba13a:
* the control flow is complex, so there are many paths through the logic to reach a point like `LAB_000ba13a`

The loop variable Phi nodes are also complex, referencing intermediate temporary varnodes

```text
0x000ba13a:10d3: a5(0x000ba13a:10d3) = a5(0x000ba142:323) ? a5(0x000b9966:121) ? a5(0x000b9966:121) ? a5(0x000b9966:121)
0x000ba13a:fe9:  a3(0x000ba13a:fe9) = a3(0x000ba144:324) ? a0(0x000b993c:2526) ? a0(0x000b993c:2526) ? a0(0x000b993c:2526)
0x000ba13a:f0c:  a1(0x000ba13a:f0c) = u0x10000594(0x000ba14c:2491) ? u0x1000059c(0x000ba134:2492) ? u0x100005a4(0x000ba360:2493) ? u0x100005ac(0x000ba244:2494)
0x000ba13a:320:  a4(0x000ba13a:320) = vsetvli_e8m1tama(a5(0x000ba13a:10d3))
```

There appear to be many instances where `vector_memcpy` transforms are feasible but blocked due to complex dependancy or heritage relationships.
Perhaps a more nuanced approach is needed rather than the simple erasure of any loop variable varnodes:

1. separate Phi nodes anchored at the top of a block into loop variable Phi nodes and other Phi nodes affecting downstream blocks
2. erase varnodes external to the loop that reference the output of vsetvli instructions - these won't have deterministic values and should never have
   descendants.
3. rewrite or generate Phi nodes capturing the expected value of registers at the end of a `vector_memcpy` transform.  For instance, the load and store
   address registers will point to the end of their respective sequences and the counter register will be zero

## Next steps

We need to make the pattern recognition more robust in the presence of complex control flow and dependency/heritage relationships.
Let's use `whisper_sample_5` as a driving test case, with some enhancements to the test framework to measure the number of completed
transforms.  We want to refactor the handling of Phi nodes to minimize the need to exhaustively collect dependencies.

This will include many iterations of a specific test:

```console
$ python integrationTest.py T1Datatests.test_03_whisper_regression
...
INFO:root:Running SLEIGHHOME=/opt/ghidra_11.4_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_sample_5.ghidra with output to /tmp/whisper_sample_5.testlog
INFO:root:Found 17 vector memcpy transforms in whisper_sample_5
```

## After refactoring and rebasing

Refactor the plugin code and rebase to the Ghidra 11.4 release.  The code recognizing vector stanzas and completing
the transforms changed significantly, so the previously reported results are no longer valid.  Let's walk through
the test cases and see if we can improve on those previous results.


### Loop-free transforms

The simplest case involves vector stanzas with no loops - where the number of vector elements is known at compile time
and known to be small enough that all elements fit into the smallest vector register (16 bytes).  The `test/memcpy_exemplars`
examples include several of these. A good example is

```as
# copy fixed 15 bytes
.extern memcpy_i15
memcpy_i15:
    vsetivli zero,0xf,e8,m1,ta,ma  
    vle8.v   v1,(a1)
    nop
    nop
    vse8.v   v1,(a0)
    ret
```

The Ghidra test script assigns this signature to the function before decompilation begins:

```c
extern void memcpy_i15(void* to, void* from);
```

>Note: the no-op instructions are present simply to test the stanza matcher with non-contiguous load and store operations.

Run this test case with:

```console
SLEIGHHOME=/opt/ghidra_11.5_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so valgrind \
  /opt/ghidra_11.5_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/memcpy_exemplars.ghidra
```

We get:

```text
...
[decomp]> load function memcpy_i15
Function memcpy_i15: 0x00000036
[decomp]> decompile memcpy_i15
Decompiling memcpy_i15
Decompilation complete
[decomp]> print C

void memcpy_i15(void *to,void *from)

{
  vector_memcpy((void *)to,(void *)from,0xf);
  return;
}
[decomp]> print raw
0
Basic Block 0 0x00000036-0x00000046
0x00000042:c:	u0x10000000(0x00000042:c) = (cast) a0(i)
0x00000042:d:	u0x10000008(0x00000042:d) = (cast) a1(i)
0x00000042:b:	vector_memcpy(u0x10000000(0x00000042:c),u0x10000008(0x00000042:d),#0xf:1)
0x00000046:a:	return(#0x0)
```

This shows a valid transform, with a few interesting traits:

* `vector_memcpy` replaces the three vector operations with the single PcodeOp at `0x00000042:b`
* The decompiler inserts two CAST PcodeOps after the transform Rule is complete.
* The decompiler window inserts some redundant casting within the call to `vector_memcpy`.
* The decompiler removes any references to the three scratch registers, `a0`, `a1`, and `v1`.
  The decompiler knows that the function hasa a void return, so `a0` and `a1` are not to be considered
  as holding the return value.

### Minimal loop transforms

`test/memcpy_exemplars` also includes an example where the compiler does not know the number of elements
to transfer.

```as
memcpy_v1:
    vsetvli  a3,a2,e8,m1,ta,ma
    vle8.v   v1,(a1)
    sub      a2,a2,a3
    c.add    a0,a3
    vse8.v   v1,(a0)
    c.add    a1,a3
    bne      a2,zero,memcpy_v1
    ret
```

The decompiler is told the signature of this function:

```c
extern void memcpy_v1(void* to, void* from, long size);
```
The test output shows a successful transform:

```text
[decomp]> load function memcpy_v1
Function memcpy_v1: 0x00000048
[decomp]> decompile memcpy_v1
Decompiling memcpy_v1
Decompilation complete
[decomp]> print C

void memcpy_v1(void *to,void *from,long size)

{
  do {
    vector_memcpy((void *)to,(void *)from,size);
  } while ;
  return;
}
[decomp]> print raw
0
Basic Block 0 0x00000048-0x00000048
Basic Block 1 0x00000048-0x0000005a
0x00000048:13:	u0x10000008(0x00000048:13) = (cast) a0(i)
0x00000048:14:	u0x10000010(0x00000048:14) = (cast) a1(i)
0x00000048:12:	vector_memcpy(u0x10000008(0x00000048:13),u0x10000010(0x00000048:14),a2(i))
Basic Block 2 0x0000005c-0x0000005c
0x0000005c:a:	return(#0x0)
```

The generated Pcode is good, with the same cast ops inserted as in the constant-size case.
The `do ... while;` wrapping is a distracting but harmless side effect of the transform.
This plugin build allows logging, so let's set the log-level to trace and see what is going on.

This version of the plugin triggers on any `vsetvli` instruction, constructing a `VectorMatcher`
object to extract features from the associated PcodeOps.  If those features are consistent with a vector_memcpy
transform, and the transform can be completed without dangling (aka "free" varnode dependencies), then the
transform is executed.

>Note: The following segments of the log file includes manual annotation flagged by `//`

```text
[2025-06-26 20:16:05.505] [riscv_vector] [info] Summary of traits:
        Vector stanza begins at 0x48
        elementSize = 1
        multiplier = 1
        code size = 0x12
[2025-06-26 20:16:05.505] [riscv_vector] [info] 
        Number of Phi nodes affected by loop = 3   // Phi nodes track writes to registers and memory
        Number of other UserPcodes = 0
        Number of arithmetic ops = 3               // We expect two pointers and one counter to be updated within the loop
[2025-06-26 20:16:05.507] [riscv_vector] [info] 
        Number of elements is constant = false
        Number of elements is variable = true
        Found simple comparison = true             // Found a simple loop condition test
        Found unexpected opcode = false            // No unexpected PcodeOps found
[2025-06-26 20:16:05.507] [riscv_vector] [info] 
        Found other user  opcode = false           // No other vector instructions found
        Found simple flow structure = true         // No other calls, returns, or branches
        Found simple load/store pattern = true     // One load, one store
        Found vector registers match = true        // Load and Store share the same vector register
[2025-06-26 20:16:05.508] [riscv_vector] [info] 
        Number of elements varnode identified = true          // Varnode input holding total number of elements found
        Number of elements per loop varnode identified = true // Varnode register holding number of elements per iteration
        Vector load address varnode identified = true         // Varnode input holding source address
        Vector store address varnode identified = true        // Varnode input holding destination address
[2025-06-26 20:16:05.508] [riscv_vector] [trace] Entering applyOp with a recognized vset* user pcode op at 0x48
[2025-06-26 20:16:05.508] [riscv_vector] [trace] Testing the vector stanza for a vector_memcpy match  // This is a match
[2025-06-26 20:16:05.511] [riscv_vector] [info] Vector loop block before transforms is  // What Pcode is given to our Rule?
Basic Block 1 0x00000048-0x0000005a
0x00000048:e:   a2(0x00000048:e) = a2(0x00000050:3) ? a2(i)   // Three Phi nodes showing register write locations
0x00000048:d:   a1(0x00000048:d) = a1(0x00000058:7) ? a1(i)
0x00000048:c:   a0(0x00000048:c) = a0(0x00000052:4) ? a0(i)
0x00000048:0:   a3(0x00000048:0) = vsetvli_e8m1tama(a2(0x00000048:e))  // The vsetvli_e8m1tama instruction
0x0000004c:2:   v1(0x0000004c:2) = vle8_v(a1(0x00000048:d))            // The vector load instruction
0x00000050:11:  u0x10000000(0x00000050:11) = a3(0x00000048:0) * #0xffffffffffffffff  // Part of the count decrementer
0x00000050:3:   a2(0x00000050:3) = a2(0x00000048:e) + u0x10000000(0x00000050:11)     // Remainder of the count decrementer
0x00000052:4:   a0(0x00000052:4) = a0(0x00000048:c) + a3(0x00000048:0) // Destination address updater
0x00000054:6:   vse8_v(v1(0x0000004c:2),a0(0x00000052:4))              // The vector Store instruction
0x00000058:7:   a1(0x00000058:7) = a1(0x00000048:d) + a3(0x00000048:0) // Source address updater
0x0000005a:8:   u0x00018500:1(0x0000005a:8) = a2(0x00000050:3) != #0x0         // Branch condition test count==0
0x0000005a:9:   goto r0x00000048:1(free) if (u0x00018500:1(0x0000005a:8) != 0) // Condintional branch

// The `VectorMatcher` has identified key Varnodes within the loop
[2025-06-26 20:16:05.512] [riscv_vector] [trace] vStore, vLoadVn, vNumElem = a0(0x00000048:c);a1(0x00000048:d);a2(0x00000048:e)
2025-06-26 20:16:05.513] [riscv_vector] [info] Transforming PcodeOp at 0x48:e
[2025-06-26 20:16:05.514] [riscv_vector] [trace]        Reducing the Phi or MULTIEQUAL node at this location
[2025-06-26 20:16:05.514] [riscv_vector] [trace]        Absorbing this PcodeOp
[2025-06-26 20:16:05.515] [riscv_vector] [trace]        Acquiring the vector number of elements varnode
[2025-06-26 20:16:05.515] [riscv_vector] [trace]        Deleting the PcodeOP (and all of its descendents)
[2025-06-26 20:16:05.516] [riscv_vector] [info] Transforming PcodeOp at 0x48:d
[2025-06-26 20:16:05.516] [riscv_vector] [trace]        Reducing the Phi or MULTIEQUAL node at this location
[2025-06-26 20:16:05.516] [riscv_vector] [trace]        Absorbing this PcodeOp
[2025-06-26 20:16:05.516] [riscv_vector] [trace]        Acquiring the vector load address varnode
[2025-06-26 20:16:05.516] [riscv_vector] [trace]        Deleting the PcodeOP (and all of its descendents)
[2025-06-26 20:16:05.516] [riscv_vector] [info] Transforming PcodeOp at 0x48:c
[2025-06-26 20:16:05.516] [riscv_vector] [trace]        Reducing the Phi or MULTIEQUAL node at this location
[2025-06-26 20:16:05.516] [riscv_vector] [trace]        Absorbing this PcodeOp
[2025-06-26 20:16:05.516] [riscv_vector] [trace]        Acquiring the vector store address varnode
[2025-06-26 20:16:05.516] [riscv_vector] [trace]        Deleting the PcodeOP (and all of its descendents)
[2025-06-26 20:16:05.516] [riscv_vector] [info] Transforming PcodeOp at 0x48:0
[2025-06-26 20:16:05.517] [riscv_vector] [trace]        Deleting the op at 0x48:0
[2025-06-26 20:16:05.517] [riscv_vector] [info] Transforming PcodeOp at 0x4c:2
[2025-06-26 20:16:05.517] [riscv_vector] [trace]        Deleting the op at 0x4c:2
[2025-06-26 20:16:05.517] [riscv_vector] [info] Transforming PcodeOp at 0x50:11
[2025-06-26 20:16:05.517] [riscv_vector] [trace]        Deleting the op at 0x50:11
[2025-06-26 20:16:05.517] [riscv_vector] [info] Transforming PcodeOp at 0x50:3
[2025-06-26 20:16:05.517] [riscv_vector] [trace]        Deleting the op at 0x50:3
[2025-06-26 20:16:05.517] [riscv_vector] [info] Transforming PcodeOp at 0x52:4
[2025-06-26 20:16:05.517] [riscv_vector] [trace]        Deleting the op at 0x52:4
[2025-06-26 20:16:05.517] [riscv_vector] [info] Transforming PcodeOp at 0x54:6
[2025-06-26 20:16:05.517] [riscv_vector] [trace]        Deleting the op at 0x54:6
[2025-06-26 20:16:05.517] [riscv_vector] [info] Transforming PcodeOp at 0x58:7
[2025-06-26 20:16:05.517] [riscv_vector] [trace]        Deleting the op at 0x58:7
[2025-06-26 20:16:05.517] [riscv_vector] [info] Transforming PcodeOp at 0x5a:8
[2025-06-26 20:16:05.517] [riscv_vector] [trace]        Deleting the op at 0x5a:8
[2025-06-26 20:16:05.518] [riscv_vector] [info] Transforming PcodeOp at 0x5a:9
[2025-06-26 20:16:05.518] [riscv_vector] [trace]        Deleting the op at 0x5a:9
[2025-06-26 20:16:05.518] [riscv_vector] [trace] Vector loop block after reducing Phi nodes is
Basic Block 1 0x00000048-0x0000005a

[2025-06-26 20:16:05.518] [riscv_vector] [info] Transforming selection into vector_memcpy, flushing log buffers
[2025-06-26 20:16:05.519] [riscv_vector] [info]         Inserting a new vector operation
                syscall[#0x11000001:4](a0(i),a1(i),a2(i))
[2025-06-26 20:16:05.520] [riscv_vector] [info] Vector loop block after all immediate transforms is
Basic Block 1 0x00000048-0x0000005a
0x00000048:12:  vector_memcpy(a0(i),a1(i),a2(i))
```

The transform has processed the three Phi or `MULTIEQUAL` PcodeOps at the top of the block, one for each of the scalar loop
variables.  All three cite two Varnodes - an internal loop register Varnode and the source varnode giving the register's
heritage at the start of the loop.  For each Phi node we need to delete the internal Varnode and replace any references
to it with the source Varnode.  The Phi PcodeOp is then deleted.

If these Phi PcodeOps cited three or more Varnodes - say a loop register Varnode and two external source Varnodes, then
we need to preserve the Phi PcodeOp and just remove the loop register Varnode, reducing the number of Varnode citations (slots)
by one.

### A simple Whisper.cpp example

We have several test functions extracted from the Whisper.cpp build.  The simplest of these is `whisper_sample_1`.
This function has a signature like `extern void string_constructor(void* this, char* param1, void* allocator)`.  It contains
two vector instruction sequences, one implementing a `strlen` call on `param1`, and the second a `memcpy` call to copy
the C string into the C++ `std::string` object.  This test:

* shows how the VectorMatch object characterizes vector loops that resemble but do not match `vector_memcpy` patterns
* shows how we can process more complex heritage/descendant relationships

The decompiler gives us (with manual annotation via `//`):

```c
void string_constructor(void *this,char *param1,void *allocator)

{
  long lVar1;
  undefined8 uVar2;
  long lVar3;
  char *pcVar4;
  long lVar5;
  undefined auVar6 [256];
  long in_vl;

  *(long *)this = (long)this + 0x10;
  if (param1 == (char *)0x0) {         // abort
    func_0x0001f950(0xfa298);          // no-return:  __throw_logic_error
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  lVar3 = 0;
  pcVar4 = param1;
  do {
    uVar2 = vsetvli_e8m1tama(0);       // number of elements is maximum supported by the hardware
    pcVar4 = pcVar4 + lVar3;           // adjust the source pointer
    auVar6 = vle8ff_v(pcVar4);         // vector load with first-fail if it would throw an access violation
    auVar6 = vmseq_vi(auVar6,0);       // vector compare with immediate 0
    lVar5 = vfirst_m(auVar6);          // find location of first source byte == 0 or -1 if not found
    lVar3 = in_vl;                     // number of bytes in a vector register
  } while (lVar5 < 0);                 // continue until a zero byte is found
  pcVar4 = pcVar4 + (lVar5 - (long)param1);  // calculate the string size
  if (pcVar4 < (char *)0x10) {         // identify the location of the string buffer
    if (pcVar4 == (char *)0x1) {
      *(char *)((long)this + 0x10) = *param1;
      goto code_r0x000209fe;
    }
    if (pcVar4 == (char *)0x0) goto code_r0x000209fe;
  }
  else {
    lVar1 = func_0x0001fad0(pcVar4 + 1,uVar2);  // operator.new(ulong size)
    *(long *)this = lVar1;
    *(char **)((long)this + 0x10) = pcVar4;
  }
  do {                                   // copy the C string into the std::string buffer
    vector_memcpy((void *)lVar1,(void *)param1,(ulong)pcVar4);
    lVar1 = (long)this + 0x10;           // this looks wrong!
  } while ;
code_r0x000209fe:
                    /* WARNING: Load size is inaccurate */
  *(char **)((long)this + 8) = pcVar4;
  pcVar4[*this] = '\0';
  return;
}
```

There are two heritage problems here, probably in our Phi node reductions:

* `lVar1` should be defined before the `vector_memcpy` builtin, not after it.
* `lVar1 = (long)this + 0x10` is true for strings of 0x10 bytes or more.

Start Ghidra's GUI with the plugin active to get some more data:

* `func_0x0001fad0` is operator.new, and takes only a single paramter.
* The variables `this` and `lVar1` both use the same register `a0`.
* simply switching the order of the two statements within the `do ... while` block
  should fix things.

Now collect data from the log file:

```text
[2025-06-27 09:36:40.938] [riscv_vector] [info] Vector loop block before transforms is
Basic Block 9 0x00020a3e-0x00020a50
0x00020a3e:a4:  a2(0x00020a3e:a4) = a2(0x00020a46:46) ? a5(0x000209ee:24) ? a5(0x000209ee:24)
0x00020a3e:9f:  a1(0x00020a3e:9f) = a1(0x00020a48:47) ? a1(i) ? a1(i)
0x00020a3e:9a:  a0(0x00020a3e:9a) = a0(0x00020a4e:4a) ? a0(0x000209c8:c) ? a0(0x00020a28:62)
0x00020a3e:43:  a3(0x00020a3e:43) = vsetvli_e8m1tama(a2(0x00020a3e:a4))
0x00020a42:45:  v1(0x00020a42:45) = vle8_v(a1(0x00020a3e:9f))
0x00020a46:cb:  u0x10000008(0x00020a46:cb) = a3(0x00020a3e:43) * #0xffffffffffffffff
0x00020a46:46:  a2(0x00020a46:46) = a2(0x00020a3e:a4) + u0x10000008(0x00020a46:cb)(*#0x1)
0x00020a48:47:  a1(0x00020a48:47) = a1(0x00020a3e:9f) + a3(0x00020a3e:43)(*#0x1)
0x00020a4a:49:  vse8_v(v1(0x00020a42:45),a0(0x00020a3e:9a))
0x00020a4e:4a:  a0(0x00020a4e:4a) = a0(0x00020a3e:9a) + a3(0x00020a3e:43)
...
[2025-06-27 09:36:40.962] [riscv_vector] [info] Vector loop block after all immediate transforms is
Basic Block 9 0x00020a3e-0x00020a50
0x00020a3e:9a:  a0(0x00020a3e:9a) = a0(0x000209c8:c) ? a0(0x00020a28:62)
0x00020a3e:e2:  vector_memcpy(a0(0x00020a3e:9a),a1(i),a5(0x000209ee:24))
```

The transformed Block 9 gets further processing from Ghidra, so the final result is different:

```text
Basic Block 9 0x00020a3e-0x00020a50
0x00020a3e:9a:	a0(0x00020a3e:9a) = u0x10000019(0x00020a50:e3) ? a0(0x00020a28:62)
0x00020a3e:ef:	u0x10000079(0x00020a3e:ef) = (cast) a0(0x00020a3e:9a)
0x00020a3e:f0:	u0x10000081(0x00020a3e:f0) = (cast) a1(i)
0x00020a3e:f1:	u0x10000089(0x00020a3e:f1) = (cast) a5(0x000209ee:24)
0x00020a3e:e2:	vector_memcpy(u0x10000079(0x00020a3e:ef),u0x10000081(0x00020a3e:f0),u0x10000089(0x00020a3e:f1))
0x00020a50:e3:	u0x10000019(0x00020a50:e3) = a0(0x000209c8:c)
```

The three cast opcodes look reasonable, but `a0(0x00020a3e:9a)` has been rewritten in a way that violates
instruction sequencing.

* does a Phi node's sequence of Varnodes matter? For example, must the first Varnode be something written within
  the block?
* is this an artifact of the Basic Block not being terminated in a branch?
    * do we need to inject a goto op at the end of the block to replace the deleted PcodeOps?
* can we find which existing Rule generates these new Varnodes?
* if we generated the cast operations ourselves would the incorrect placement be avoided?
* should the vector_memcpy be inserted at the end of the block instead of the beginning?
* do we need a survey of the builtin actions to see what might be inserting these new pcodeops?

Extend the code to insert a CPUI_BRANCH opcode to end the block and flow correctly into the following block.  The new Pcode produced by the decompiler becomes:

```text
Basic Block 9 0x00020a3e-0x00020a50
0x00020a3e:9a:	a0(0x00020a3e:9a) = u0x10000019(0x00020a50:e4) ? a0(0x00020a28:62)
0x00020a3e:f0:	u0x10000079(0x00020a3e:f0) = (cast) a0(0x00020a3e:9a)
0x00020a3e:f1:	u0x10000081(0x00020a3e:f1) = (cast) a1(i)
0x00020a3e:f2:	u0x10000089(0x00020a3e:f2) = (cast) a5(0x000209ee:24)
0x00020a3e:e2:	vector_memcpy(u0x10000079(0x00020a3e:f0),u0x10000081(0x00020a3e:f1),u0x10000089(0x00020a3e:f2))
0x00020a50:e4:	u0x10000019(0x00020a50:e4) = a0(0x000209c8:c)
0x00020a50:e3:	goto r0x000209fe:1(free)
Basic Block 10 0x000209fe-0x00020a0e
```

The decompiled C remains about the same:

```c
  do {
    vector_memcpy((void *)lVar1,(void *)param1,(ulong)pcVar4);
    lVar1 = (long)this + 0x10;
  } while ;
code_r0x000209fe:
                    /* WARNING: Load size is inaccurate */
  *(char **)((long)this + 8) = pcVar4;
  pcVar4[*this] = '\0';
  return;
```

## Possible Next steps

There are now many paths we can take, probably to be cast into a set of formal Issues:

1. Iterate on the code base until we eliminate any decompiler crashes across all of whisper.cpp.
2. Iterate on the code base until all current integration data tests pass.
3. Extend to code to increase the number of successful vector transforms.
4. Localize the Phi node error breaking the `lVar1` linkage to `this` in the example above.
5. Localize the decompiler failure to remove redundant cast operations associated with
   the typed builtin functions.
6. Document the existing decompiler hierarchy of Actions, localizing Phi and casting Actions
   that may run after the Plugin action and the actions that produce the DoWhile block.
7. Experiment with BlockGraph editing to remove the DoWhile block entirely.

## Debugging a decompiler failure

One of the most common debugging challenges involves the error message
`Low-level ERROR: Free varnode has multiple descendants`.  This usually means a dependency has
been improperly erased, leaving a dangling reference.  One of the integration tests currently throws
this error - let's see if we can fix it.

The command sequence to throw this error is:

```console
$ SLEIGHHOME=/opt/ghidra_11.5_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_11.5_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_sample_5.ghidra with output to /tmp/whisper_sample_5.testlog
[decomp]> restore test/whisper_sample_5_save.xml
test/whisper_sample_5_save.xml successfully loaded: RISC-V 64 little general purpose compressed
[decomp]> map function 0xb97c0 whisper_wrap_segment
[decomp]> parse line extern void whisper_wrap_segment(void*, void*, int, int);
[decomp]> load function whisper_wrap_segment
Function whisper_wrap_segment: 0x000b97c0
[decomp]> decompile whisper_wrap_segment
Decompiling whisper_wrap_segment
Low-level ERROR: Free varnode has multiple descendants
Unable to proceed with function: whisper_wrap_segment
[decomp]> print C
Execution error: No function selected
[decomp]> print raw
Execution error: No function selected
```

The logfile shows some good hints at the problem:

```text
/tmp$ grep -E vector_\.*\(free\) ghidraRiscvLogger.log
0x000ba438:2490:	vector_memcpy(s6(0x000b9bbc:439),a0(free),a7(0x000b9bc4:43d))
0x000ba4e8:2494:	vector_memcpy(s0xffffffffffffff10(0x000b9de0:1c12),s6(0x000b9dfe:5a2),a0(free))
0x000ba550:2498:	vector_memcpy(s0xffffffffffffff10(0x000b9de0:1c12),s6(0x000b9dfe:5a2),a2(free))
```

The three `free` varnodes should be fully resolved.

```text
[2025-06-29 13:25:02.504] [riscv_vector] [info] Vector loop block before transforms is
Basic Block 152 0x000ba4d6-0x000ba4e8
0x000ba4d6:116b:        a7(0x000ba4d6:116b) = s6(0x000b9dfe:5a2) ? a7(0x000ba4e0:5fd)
0x000ba4d6:1113:        a6(0x000ba4d6:1113) = s0xffffffffffffff10(0x000b9de0:1c12) ? a6(0x000ba4e6:600)
0x000ba4d6:e86: a0(0x000ba4d6:e86) = u0x100002cb(0x000ba4d6:23de) ? a0(0x000ba4de:5fc)
0x000ba4d6:5f9: a3(0x000ba4d6:5f9) = vsetvli_e8m1tama(a0(0x000ba4d6:e86))
0x000ba4da:5fb: v1(0x000ba4da:5fb) = vle8_v(a7(0x000ba4d6:116b))
0x000ba4de:13a2:        u0x100001e0(0x000ba4de:13a2) = a3(0x000ba4d6:5f9) * #0xffffffffffffffff
0x000ba4de:5fc: a0(0x000ba4de:5fc) = a0(0x000ba4d6:e86) + u0x100001e0(0x000ba4de:13a2)
0x000ba4e0:5fd: a7(0x000ba4e0:5fd) = a7(0x000ba4d6:116b) + a3(0x000ba4d6:5f9)
0x000ba4e2:5ff: vse8_v(v1(0x000ba4da:5fb),a6(0x000ba4d6:1113))
0x000ba4e6:600: a6(0x000ba4e6:600) = a6(0x000ba4d6:1113) + a3(0x000ba4d6:5f9)
0x000ba4e8:601: u0x00018500:1(0x000ba4e8:601) = a0(0x000ba4de:5fc) != #0x0
0x000ba4e8:602: goto r0x000ba4d6:1(free) if (u0x00018500:1(0x000ba4e8:601) != 0)
```

The reference to `u0x100002cb(0x000ba4d6:23de)` looks particularly odd.  It looks to have been erased
before the transform was started, perhaps by mistake with a prior transform.  The sequence number
looks suspiciously high as well.

Modify the source to get a bit more diagnostic information:

* flush the logs after every completed transform
* terminate vector loop transforms just after the failure occurs.

The first vector stanza causing the problem is:

```text
Basic Block 83 0x000ba426-0x000ba438
0x000ba426:1043:        a4(0x000ba426:1043) = a4(0x000ba42e:85b) ? a7(0x000b9bc4:43d)
0x000ba426:eef: a1(0x000ba426:eef) = a1(0x000ba436:85f) ? a0(0x000b9f00:7f3)
0x000ba426:e92: a0(0x000ba426:e92) = a0(0x000ba430:85c) ? s6(0x000b9bbc:439)
0x000ba426:858: a3(0x000ba426:858) = vsetvli_e8m1tama(a4(0x000ba426:1043))
0x000ba42a:85a: v1(0x000ba42a:85a) = vle8_v(a0(0x000ba426:e92))
0x000ba42e:139b:        u0x100001b8(0x000ba42e:139b) = a3(0x000ba426:858) * #0xffffffffffffffff
0x000ba42e:85b: a4(0x000ba42e:85b) = a4(0x000ba426:1043) + u0x100001b8(0x000ba42e:139b)
0x000ba430:85c: a0(0x000ba430:85c) = a0(0x000ba426:e92) + a3(0x000ba426:858)
0x000ba432:85e: vse8_v(v1(0x000ba42a:85a),a1(0x000ba426:eef))
0x000ba436:85f: a1(0x000ba436:85f) = a1(0x000ba426:eef) + a3(0x000ba426:858)
0x000ba438:860: u0x00018500:1(0x000ba438:860) = a4(0x000ba42e:85b) != #0x0
0x000ba438:861: goto r0x000ba426:1(free) if (u0x00018500:1(0x000ba438:860) != 0)
```

The failing transform is:


```text
Basic Block 83 0x000ba426-0x000ba438
0x000ba438:2490:        vector_memcpy(s6(0x000b9bbc:439),a0(free),a7(0x000b9bc4:43d))
0x000ba438:2491:        goto r0x000ba43a:1(free)
```

The correct transform would be:

```text
0x000ba438:2490:        vector_memcpy(a0(0x000b9f00:7f3), s6(0x000b9bbc:439),a7(0x000b9bc4:43d))
```

The problem is likely the mixed registers found in the Phi ops.  Fixing that uncovers another error.

```text
Basic Block 42 0x000ba13a-0x000ba14c
0x000ba13a:23fd:        t1(0x000ba13a:23fd) = t1(0x000ba13a:23fd) ? t1(0x000ba130:e2c) ? t1(0x000ba35c:e2e) ? t1(0x000ba240:e2a)
0x000ba13a:23fc:        s2(0x000ba13a:23fc) = s2(0x000ba13a:23fc) ? s2(0x000ba130:1193) ? s2(0x000ba35c:1194) ? s2(0x000ba240:119d)
0x000ba13a:23fb:        vl(0x000ba13a:23fb) = vl(0x000ba13a:23fb) ? vl(0x000ba130:1339) ? vl(0x000ba35c:133c) ? vl(0x000ba240:133a)
0x000ba13a:23fa:        r0x001428b0(0x000ba13a:23fa) = r0x001428b0(0x000ba13a:23fa) ? r0x001428b0(0x000ba130:142c) ? r0x001428b0(0x000ba35c:1427) ? r0x001428b0(0x000ba240:142d)
0x000ba13a:23f9:        r0x00142ab8(0x000ba13a:23f9) = r0x00142ab8(0x000ba13a:23f9) ? r0x00142ab8(0x000ba130:14cd) ? r0x00142ab8(0x000ba35c:14c8) ? r0x00142ab8(0x000ba240:14ce)
0x000ba13a:23f8:        r0x00142ba0(0x000ba13a:23f8) = r0x00142ba0(0x000ba13a:23f8) ? r0x00142ba0(0x000ba130:156e) ? r0x00142ba0(0x000ba35c:1569) ? r0x00142ba0(0x000ba240:156f)
0x000ba13a:23f7:        s0xfffffffffffffeb8(0x000ba13a:23f7) = s0xfffffffffffffeb8(0x000ba13a:23f7) ? s0xfffffffffffffeb8(0x000ba130:19bb) ? s0xfffffffffffffeb8(0x000ba35c:19be) ? s0xfffffffffffffeb8(0x000ba240:19bc)
0x000ba13a:23f6:        s0xfffffffffffffec0(0x000ba13a:23f6) = s0xfffffffffffffec0(0x000ba13a:23f6) ? s0xfffffffffffffec0(0x000ba130:1a0c) ? s0xfffffffffffffec0(0x000ba35c:1a0f) ? s0xfffffffffffffec0(0x000ba240:1a0d)
0x000ba13a:23f5:        s0xfffffffffffffec8(0x000ba13a:23f5) = s0xfffffffffffffec8(0x000ba13a:23f5) ? s0xfffffffffffffec8(0x000ba130:1a60) ? s0xfffffffffffffec8(0x000ba35c:1a63) ? s0xfffffffffffffec8(0x000ba240:1a61)
0x000ba13a:23f4:        s0xfffffffffffffed8(0x000ba13a:23f4) = s0xfffffffffffffed8(0x000ba13a:23f4) ? s0xfffffffffffffed8(0x000ba130:1ab0) ? s0xfffffffffffffed8(0x000ba35c:1ab3) ? s0xfffffffffffffed8(0x000ba240:1ab1)
0x000ba13a:23f3:        s0xfffffffffffffee0(0x000ba13a:23f3) = s0xfffffffffffffee0(0x000ba13a:23f3) ? s0xfffffffffffffee0(0x000ba130:1afe) ? s0xfffffffffffffee0(0x000ba35c:1b01) ? s0xfffffffffffffee0(0x000ba240:1aff)
0x000ba13a:23f2:        s0xfffffffffffffee8(0x000ba13a:23f2) = s0xfffffffffffffee8(0x000ba13a:23f2) ? s0xfffffffffffffee8(0x000ba130:1b4c) ? s0xfffffffffffffee8(0x000ba35c:1b4f) ? s0xfffffffffffffee8(0x000ba240:1b4d)
0x000ba13a:23f1:        s0xfffffffffffffef8(0x000ba13a:23f1) = s0xfffffffffffffef8(0x000ba13a:23f1) ? s0xfffffffffffffef8(0x000ba130:1b9a) ? s0xfffffffffffffef8(0x000ba35c:1b9d) ? s0xfffffffffffffef8(0x000ba240:1b9b)
0x000ba13a:23f0:        s0xffffffffffffff08:4(0x000ba13a:23f0) = s0xffffffffffffff08:4(0x000ba13a:23f0) ? s0xffffffffffffff08:4(0x000ba130:1be8) ? s0xffffffffffffff08:4(0x000ba35c:1beb) ? s0xffffffffffffff08:4(0x000ba240:1be9)
0x000ba13a:23ef:        s0xffffffffffffff10(0x000ba13a:23ef) = s0xffffffffffffff10(0x000ba13a:23ef) ? s0xffffffffffffff10(0x000ba130:1c36) ? s0xffffffffffffff10(0x000ba35c:1c39) ? s0xffffffffffffff10(0x000ba240:1c37)
0x000ba13a:23ee:        s0xffffffffffffff18(0x000ba13a:23ee) = s0xffffffffffffff18(0x000ba13a:23ee) ? s0xffffffffffffff18(0x000ba130:1c85) ? s0xffffffffffffff18(0x000ba35c:1c88) ? s0xffffffffffffff18(0x000ba240:1c86)
0x000ba13a:23ed:        s0xffffffffffffff20(0x000ba13a:23ed) = s0xffffffffffffff20(0x000ba13a:23ed) ? s0xffffffffffffff20(0x000ba130:1cd2) ? s0xffffffffffffff20(0x000ba35c:1cd5) ? s0xffffffffffffff20(0x000ba240:1cd3)
0x000ba13a:23ec:        s0xffffffffffffff28:1(0x000ba13a:23ec) = s0xffffffffffffff28:1(0x000ba13a:23ec) ? s0xffffffffffffff28:1(0x000ba130:1d21) ? s0xffffffffffffff28:1(0x000ba35c:1d25) ? s0xffffffffffffff28:1(0x000ba240:1d22)
0x000ba13a:23eb:        s0xffffffffffffff40(0x000ba13a:23eb) = s0xffffffffffffff40(0x000ba13a:23eb) ? s0xffffffffffffff40(0x000ba130:1d6e) ? s0xffffffffffffff40(0x000ba35c:1d71) ? s0xffffffffffffff40(0x000ba240:1d6f)
0x000ba13a:23ea:        s0xffffffffffffff48(0x000ba13a:23ea) = s0xffffffffffffff48(0x000ba13a:23ea) ? s0xffffffffffffff48(0x000ba130:1dbc) ? s0xffffffffffffff48(0x000ba35c:1dbf) ? s0xffffffffffffff48(0x000ba240:1dbd)
0x000ba13a:23e9:        s0xffffffffffffff50(0x000ba13a:23e9) = s0xffffffffffffff50(0x000ba13a:23e9) ? s0xffffffffffffff50(0x000ba130:1e0a) ? s0xffffffffffffff50(0x000ba35c:1e0d) ? s0xffffffffffffff50(0x000ba240:1e0b)
0x000ba13a:23e8:        s0xffffffffffffff60:4(0x000ba13a:23e8) = s0xffffffffffffff60:4(0x000ba13a:23e8) ? s0xffffffffffffff60:4(0x000ba130:1e58) ? s0xffffffffffffff60:4(0x000ba35c:1e5b) ? s0xffffffffffffff60:4(0x000ba240:1e59)
0x000ba13a:23e7:        s0xffffffffffffff68(0x000ba13a:23e7) = s0xffffffffffffff68(0x000ba13a:23e7) ? s0xffffffffffffff68(0x000ba130:1ea6) ? s0xffffffffffffff68(0x000ba35c:1ea9) ? s0xffffffffffffff68(0x000ba240:1ea7)
0x000ba13a:23e6:        s0xffffffffffffff78(0x000ba13a:23e6) = s0xffffffffffffff78(0x000ba13a:23e6) ? s0xffffffffffffff78(0x000ba130:1ef4) ? s0xffffffffffffff78(0x000ba35c:1ef7) ? s0xffffffffffffff78(0x000ba240:1ef5)
0x000ba13a:23e5:        s0xffffffffffffff80:1(0x000ba13a:23e5) = s0xffffffffffffff80:1(0x000ba13a:23e5) ? s0xffffffffffffff80:1(0x000ba130:1f42) ? s0xffffffffffffff80:1(0x000ba35c:1f45) ? s0xffffffffffffff80:1(0x000ba240:1f43)
0x000ba13a:23e4:        s0xffffffffffffff88(0x000ba13a:23e4) = s0xffffffffffffff88(0x000ba13a:23e4) ? s0xffffffffffffff88(0x000ba130:1f90) ? s0xffffffffffffff88(0x000ba35c:1f93) ? s0xffffffffffffff88(0x000ba240:1f91)
0x000ba13a:10d3:        a5(0x000ba13a:10d3) = a5(0x000ba142:323) ? a5(0x000b9966:121) ? a5(0x000b9966:121) ? a5(0x000b9966:121)
0x000ba13a:fe9: a3(0x000ba13a:fe9) = a3(0x000ba144:324) ? a0(0x000b993c:10a) ? a0(0x000b993c:10a) ? a0(0x000b993c:10a)
0x000ba13a:f0c: a1(0x000ba13a:f0c) = a1(0x000ba14a:327) ? a1(0x000ba132:31c) ? a1(0x000ba35e:33e) ? t1(0x000ba240:e2a)
0x000ba13a:320: a4(0x000ba13a:320) = vsetvli_e8m1tama(a5(0x000ba13a:10d3))
0x000ba13e:322: v1(0x000ba13e:322) = vle8_v(a3(0x000ba13a:fe9))
0x000ba142:138c:        u0x10000158(0x000ba142:138c) = a4(0x000ba13a:320) * #0xffffffffffffffff
0x000ba142:323: a5(0x000ba142:323) = a5(0x000ba13a:10d3) + u0x10000158(0x000ba142:138c)(*#0x1)
0x000ba144:324: a3(0x000ba144:324) = a3(0x000ba13a:fe9) + a4(0x000ba13a:320)(*#0x1)
0x000ba146:326: vse8_v(v1(0x000ba13e:322),a1(0x000ba13a:f0c))
0x000ba14a:327: a1(0x000ba14a:327) = a1(0x000ba13a:f0c) + a4(0x000ba13a:320)
0x000ba14c:328: u0x00018500:1(0x000ba14c:328) = a5(0x000ba142:323) != #0x0
0x000ba14c:329: goto r0x000ba13a:1(free) if (u0x00018500:1(0x000ba14c:328) != 0)
...
vector_memcpy(<null>,a0(0x000b993c:10a),a5(0x000b9966:121))
```

There are two problems here:

1. The large number of Phi nodes referencing stack variables unassociated with the vector loop adds distracting clutter.  The code
   processes these nodes to check for interior loop references and to remove duplicate Varnodes - can we suppress printing these in `trace` mode?
2. The code currently extracts vector parameters from Phi nodes with only two Varnodes after duplicate removal.  That's true for `a3` and `a5`,
   but not for `a1`.  The code should remove duplicate Varnodes and search for vector parameters regardless of the number of unique
   varnodes.

Fix the extraction and rerun tests.  All integration tests pass.  Running the plugin with the Ghidra GUI shows:

* 560 `vector_memcpy` transforms
* 195 `vector_memset` transforms
* 215 decompiler process failures

```console
$ grep Unable whisper_cpp_rva23.c
Unable to decompile 'set_xterm256_foreground'
Unable to decompile 'set_xterm256_foreground'
Unable to decompile '__static_initialization_and_destruction_0'
Unable to decompile '_start'
Unable to decompile 'drwav_init_write__internal'
Unable to decompile 'drwav_target_write_size_bytes'
Unable to decompile 'drwav_read_pcm_frames_be'
Unable to decompile 'drwav_write_pcm_frames_be.part.0'
Unable to decompile 'drwav_f32_to_s16'
...
```

Looks like we need more integration tests.  We'll use the built-in Ghidra decompiler ability to export functions for testing,
generating `test/whisper_sample_6_save.xml` from `drwav_f32_to_s16`.  It's easy to generate a matching script `test/whisper_sample_6.ghidra`.
The problem lies with instructions like

```as
fli.s   fa3
```

This instruction is part of the zfa extension, and incompletely implemented in our isa_ext SLEIGH directory.  It generates a CALL_OTHER operation
without an input Varnode.  The correction is simple - return early from the `apply` function if we are not given either a `vset` or `vseti` instruction.

With that change the Ghidra GUI whole-program decompilation is much more successful:

* 957 `vector_memcpy` transforms
* 420 `vector_memset` transforms
* 46 decompiler process failures

Pick one of those failures to continue: `quantize_q4_0`.  The failure here is a free varnode with multiple dependencies, possibly caused by
a non-loop transform failure.

Create a new integration test out of this function, calling it `whisper_sample_7`.
The error thrown is:

```text
Low-level ERROR: Free varnode has multiple descendants
```

We don't get information on *which* free varnode is causing the problems.  The log file
shows no free varnodes, so it is likely we are deleting an opcode without checking for descendents.

```text
$ grep Delet ghidraRiscvLogger.log
[info] Deleting vector op at 0x9791a
[info] Deleting vector op at 0x97922
[info] Deleting vector op at 0x9792a
[info] Deleting vector op at 0x97936
[info] Deleting vector op at 0x9793e
[info] Deleting vector op at 0x9794a
[info] Deleting vector op at 0x9794e
[info] Deleting vector op at 0x9795a
[info] Deleting vector op at 0x97a52
[info] Deleting vector op at 0x97aa2
[info] Deleting vector op at 0x97aa6
[info] Deleting vector op at 0x97972
[info] Deleting vector op at 0x9797e
[warning] Deleting orphan vset op at 0x97a46
```

Nothing in this function looks like it should trigger any vector_memcpy or vector_memset transforms

Iterate on this to find several things to fix:

* If the transform code would delete a PcodeOp with dependencies, abort the transform.  This helps
  minimize free varnodes.
* Ghidra will delete output Varnodes if it believes the destination is not used before it is overwritten.
  This causes failures when those output Varnodes are silent dependencies of other instructions,
  such as vfmacc and vslide instructions.  These require changes to make the transform code more robust
  and to fix the SLEIGH definitions to include output registers as additional input registers.

The fixes include:

* update the RISC-V SLEIGH files to show as input parameters registers that are both read and written
  during the instruction.  This includes `vfmacc`, `vfnmacc`, `vfnmadd`, `vfnmsacc`, `vfnmsub`, `vfslide1down`,
  `vfslide1up`, `vslide1down`, `vslide1up`, `vslidedown`, and `vslideup` instructions.
* rebase the Ghidra developer's tip at `ghidra_12.0_DEV` - while continuing to use the `ghidra_11.5` release
  source code for the decompiler.

At this point all integration tests pass - except for those that fail a datatest while passing in the GUI,
and where we suspect a structural error in the test case files.

The Ghidra GUI whole-program decompilation looks better:

* 468 `vector_memcpy` transforms
* 1111 `vector_memset` transforms
* 0 decompiler process failures