---
title: Walkthrough Examples
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
