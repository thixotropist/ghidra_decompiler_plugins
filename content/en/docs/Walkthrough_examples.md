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
saving it to xml and converting it into `test/whisper_sample_1.xml` and `test/whisper_sample_1.ghidra`.  This sample includes two vsetvli loops,
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