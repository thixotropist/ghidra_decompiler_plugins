---
title: Puzzles
description: Ghidra provides lots of puzzles - aka learning exercises or case studies
weight: 100
---

## Phi or MULTIEQUAL exercises

Ghidra's decompiler tries to convert binary instructions into a [Static Single Assignment](https://en.wikipedia.org/wiki/Static_single-assignment_form) form.
Part of that involves the construction of Phi junctions or nodes, showing the various possible setters for a given variable (register, stack, RAM, parameter, control and status register, ...).
Ghidra uses MULTIEQUAL PcodeOps to represent these junctions, identified internally with the `CPUI_MULTIEQUAL` opcode.  These typically appear at the start
of a decompiler Block with two or more input edges.  Any change to existing Pcode is likely to perturb these linkages.

In general, this site uses Phi and MULTIEQUAL interchangeably, often referring to these PcodeOps as 'nodes'.  Decompiler code mentioning 'heritage' likely refers to the process'
of generating these PcodeOps.  Code mentioning 'descendents' likely refers to traversing the nodes of this MULTIEQUAL PcodeOp graph.

See the [Raw_Pcode]({{< relref "../Raw_Pcode.md" >}}) page for Pcode examples, including `CPUI_MULTIEQUAL` PcodeOps.

### Phi node equivalent terms

A `strlen` test case starts with this assembly code:
```as
strlen_var1:
    c.li       a5,0x0
    c.mv       s5,a0
    bne        a0,zero,LAB_ram_000221f6
    jal        no_return
LAB_ram_000221f6:
    c.add      a0,a5                        # loop starts with add, not vset
    vsetvli    a5,zero,e8,m1,ta,ma
    vle8ff.v   v1,(a0)
    vmseq.vi   v1,v1,0x0
    csrr       a5,vl
    vfirst.m   a4,v1
    blt        a4,zero,LAB_ram_000221f6
    lbu        s10,0x0(s5)                  # not part of strlen
    c.add      a0,a4
    sub        a0,a0,s5
    ret
LAB_ram_00023054:
    c.li    a0,0x0
    ret

```

The final raw Pcode is:

```text
Basic Block 0 0x00100026-0x0010002a
0x00100026:1:	a5(0x00100026:1) = #0x0
0x0010002a:3:	u0x0002f700:1(0x0010002a:3) = a0(i) == #0x0
0x0010002a:2c:	u0x1000001a(0x0010002a:2c) = a0(i)
0x0010002a:2e:	u0x1000002a(0x0010002a:2e) = a5(0x00100026:1)
0x0010002a:4:	goto Block_1:0x0010002c if (u0x0002f700:1(0x0010002a:3) != 0) else Block_2:0x00100030
Basic Block 1 0x0010002c-0x0010002c
0x0010002c:22:	a5(0x0010002c:22) = [create] i0x0010002c:6(free)
0x0010002c:27:	c0x0c20(0x0010002c:27) = c0x0c20(i) [] i0x0010002c:6(free)
0x0010002c:6:	u0x10000042(0x0010002c:6) = call ffunc_0x00101000(free)
0x0010002c:31:	a0(0x0010002c:31) = (cast) u0x10000042(0x0010002c:6)
0x0010002c:2d:	u0x10000022(0x0010002c:2d) = a5(0x0010002c:22)
0x0010002c:2f:	u0x10000032(0x0010002c:2f) = u0x10000022(0x0010002c:2d)
Basic Block 2 0x00100030-0x00100046
0x00100030:29:	c0x0c20(0x00100030:29) = c0x0c20(i) ? c0x0c20(0x0010002c:27) ? c0x0c20(0x00100030:29)
0x00100030:23:	a5(0x00100030:23) = u0x1000002a(0x0010002a:2e) ? u0x10000032(0x0010002c:2f) ? u0x1000003a(0x00100046:30)
0x00100030:1f:	a0(0x00100030:1f) = u0x1000001a(0x0010002a:2c) ? a0(0x0010002c:31) ? a0(0x00100030:7)
0x00100030:7:	a0(0x00100030:7) = a0(0x00100030:1f) + a5(0x00100030:23)(*#0x1)
0x00100032:8:	vsetvli_e8m1tama(#0x0)
0x00100036:a:	v1(0x00100036:a) = vle8ff_v(a0(0x00100030:7))
0x0010003a:c:	v1(0x0010003a:c) = vmseq_vi(v1(0x00100036:a),#0x0)
0x00100042:e:	a4(0x00100042:e) = vfirst_m(v1(0x0010003a:c))
0x00100046:f:	u0x00004100:1(0x00100046:f) = a4(0x00100042:e) < #0x0
0x00100046:30:	u0x1000003a(0x00100046:30) = c0x0c20(0x00100030:29)
0x00100046:10:	goto Block_2:0x00100030 if (u0x00004100:1(0x00100046:f) != 0) else Block_3:0x0010004a
Basic Block 3 0x0010004a-0x00100054
0x00100050:32:	u0x1000004a(0x00100050:32) = (cast) a0(i)
0x00100050:2b:	u0x10000012(0x00100050:2b) = a4(0x00100042:e) - u0x1000004a(0x00100050:32)
0x00100050:16:	a0(0x00100050:16) = a0(0x00100030:7) + u0x10000012(0x00100050:2b)(*#0x1)
0x00100054:28:	c0x0c20(0x00100054:28) = c0x0c20(0x00100030:29)
0x00100054:33:	u0x10000052(0x00100054:33) = (cast) a0(0x00100050:16)
0x00100054:17:	return(#0x0) u0x10000052(0x00100054:33)
```

The vector loop begins with three PHI nodes:

```text
Basic Block 2 0x00100030-0x00100046
0x00100030:29:	c0x0c20(0x00100030:29) = c0x0c20(i) ? c0x0c20(0x0010002c:27) ? c0x0c20(0x00100030:29)
0x00100030:23:	a5(0x00100030:23) = u0x1000002a(0x0010002a:2e) ? u0x10000032(0x0010002c:2f) ? u0x1000003a(0x00100046:30)
0x00100030:1f:	a0(0x00100030:1f) = u0x1000001a(0x0010002a:2c) ? a0(0x0010002c:31) ? a0(0x00100030:7)
```

The Varnode `a0(0x00100030:1f)` provides the vector load address.  It has three heritage Varnodes:

1. `a0(0x00100030:7)` is internal to the loop
2. `a0(0x0010002c:31)` is external to the loop and should likely be used in a transform as `vector_strlen(a0(0x0010002c:31))`
3. `u0x1000001a(0x0010002a:2c)` is also external to the loop and could *also* be used in a transform as `vector_strlen(u0x1000001a(0x0010002a:2c))`

The puzzle: how do we know which of the two external Varnodes is the correct one to use in our transform?  This test case is
slightly misleading, as the call to `ffunc_0x00101000` *should* have been marked as `noreturn`.  If we update the test script to
set the noreturn option, then the heritage calculation drops the reference to the third Varnode and the transform completes.

The remaining puzzle is how to properly reduce a 3-term Phi node to a 2-term Phi node when two of the terms are equivalent.

### Control and status register Phi nodes

Control and status registers - CSRs - are treated like regular registers in that they
collect Phi node operations.  That raises some issues when vector CSRs are involved,
as Ghidra's decompiler can't easily track their heritages.  It tries anyway, adding
complexity to the Pcode.

Take the specific case of the `vl` register, the `vector length` register.  This register is written automatically by every `vsetvli` or `vsetivli` instruction,
and by `vle*ff` instructions.  It's read by almost all vector instructions.  Vector loops processing an indeterminate number of elements may need to access this register,
mostly to allow proper handling of recoverable page faults.

RISC-V binaries including a vectorization of the `strlen` or `strcmp` functions need
explicit access to this `vl` register.  The Ghidra listing view can look like this:

```text
LAB_ram_000209d2:
  vsetvli  param_2,zero,e8,m1,ta,ma
  c.add    a5,a3
  vle8ff.v v1,(a5)
  vmseq.vi v1,v1,0x0
  csrr     a3,vl
  vfirst.m a6,v1
  blt      a6,zero,LAB_ram_000209d2
```

and the Ghidra Decompiler view like this:

```c
do {
  vsetvli_e8m1tama(0);
  pcVar4 = pcVar4 + lVar3;
  auVar6 = vle8ff_v(pcVar4);
  auVar6 = vmseq_vi(auVar6,0);
  lVar5 = vfirst_m(auVar6);
  lVar3 = _vl;
} while (lVar5 < 0);
```

The Decompiler pcode for this function looks like:

```text
Basic Block 0 0x000209be-0x000209cc
...
Basic Block 1 0x00020a54-0x00020a5c
0x00020a5c:c3:	c0x0c20(0x00020a5c:c3) = c0x0c20(i) [] i0x00020a5c:73(free)
0x00020a5c:73:	call ffunc_0x0001f950(free)
0x00020a5c:c6:	c0x0c20(0x00020a5c:c6) = c0x0c20(0x00020a5c:c3)
0x00020a5c:74:	return(#0x1:4)
Basic Block 2 0x000209ce-0x000209d0
0x000209ce:13:	a3(0x000209ce:13) = #0x0
0x000209d0:e3:	u0x10000043(0x000209d0:e3) = a3(0x000209ce:13)
0x000209d0:e5:	u0x10000053(0x000209d0:e5) = a1(i)
Basic Block 3 0x000209d2-0x000209e8
0x000209d2:b4:	a5(0x000209d2:b4) = u0x10000053(0x000209d0:e5) ? a5(0x000209d6:16)
0x000209d2:ab:	a3(0x000209d2:ab) = u0x10000043(0x000209d0:e3) ? u0x1000004b(0x000209e8:e4)
0x000209d2:15:	a2(0x000209d2:15) = vsetvli_e8m1tama(#0x0)
0x000209d6:16:	a5(0x000209d6:16) = a5(0x000209d2:b4) + a3(0x000209d2:ab)(*#0x1)
0x000209d8:18:	v1(0x000209d8:18) = vle8ff_v(a5(0x000209d6:16))
0x000209dc:1a:	v1(0x000209dc:1a) = vmseq_vi(v1(0x000209d8:18),#0x0)
0x000209e4:1c:	a6(0x000209e4:1c) = vfirst_m(v1(0x000209dc:1a))
0x000209e8:1d:	u0x00004100:1(0x000209e8:1d) = a6(0x000209e4:1c) < #0x0
0x000209e8:e4:	u0x1000004b(0x000209e8:e4) = c0x0c20(i)
0x000209e8:1e:	goto Block_3:0x000209d2 if (u0x00004100:1(0x000209e8:1d) != 0) else Block_4:0x000209ec
Basic Block 4 0x000209ec-0x000209f2
0x000209ee:e9:	u0x10000073(0x000209ee:e9) = (cast) a1(i)
0x000209ee:df:	u0x10000023(0x000209ee:df) = a6(0x000209e4:1c) - u0x10000073(0x000209ee:e9)
0x000209ee:20:	a5(0x000209ee:20) = a5(0x000209d6:16) + u0x10000023(0x000209ee:df)(*#0x1)
0x000209f2:23:	u0x00004200:1(0x000209f2:23) = a5(0x000209ee:20) < #0x10
0x000209f2:e6:	u0x1000005b(0x000209f2:e6) = a5(0x000209ee:20)
0x000209f2:24:	goto Block_6:0x000209f6 if (u0x00004200:1(0x000209f2:23) != 0) else Block_5:0x00020a18
Basic Block 5 0x00020a18-0x00020a3a
0x00020a18:53:	a0(0x00020a18:53) = a5(0x000209ee:20) + #0x1(*#0x1)
0x00020a28:c4:	c0x0c20(0x00020a28:c4) = c0x0c20(i) [] i0x00020a28:5e(free)
0x00020a28:5e:	a0(0x00020a28:5e) = call ffunc_0x0001fad0(free)(a0(0x00020a18:53),a1(i),a2(0x000209d2:15))
0x00020a38:ea:	u0x1000007b(0x00020a38:ea) = (cast) a0(i)
0x00020a38:6a:	*(ram,u0x1000007b(0x00020a38:ea)) = a0(0x00020a28:5e)
0x00020a3a:eb:	u0x10000083(0x00020a3a:eb) = (cast) a0(i)
0x00020a3a:6c:	u0x1000008b(0x00020a3a:6c) = u0x10000083(0x00020a3a:eb) + #0x10
0x00020a3a:ec:	u0x00031000(0x00020a3a:ec) = (cast) u0x1000008b(0x00020a3a:6c)
0x00020a3a:6d:	*(ram,u0x00031000(0x00020a3a:ec)) = a5(0x000209ee:20)
0x00020a3a:   	[ goto Block_9:0x00020a3e ]
Basic Block 6 0x000209f6-0x000209f8
0x000209f8:27:	u0x00003e00:1(0x000209f8:27) = a5(0x000209ee:20) == #0x1
0x000209f8:28:	goto Block_7:0x00020a10 if (u0x00003e00:1(0x000209f8:27) != 0) else Block_8:0x000209fc
Basic Block 7 0x00020a10-0x00020a16
0x00020a10:4c:	u0x0008ac00:1(0x00020a10:4c) = *(ram,a1(i))
0x00020a12:ed:	u0x10000093(0x00020a12:ed) = (cast) a0(i)
0x00020a12:4f:	u0x1000009b(0x00020a12:4f) = u0x10000093(0x00020a12:ed) + #0x10
0x00020a12:ee:	u0x00006c00(0x00020a12:ee) = (cast) u0x1000009b(0x00020a12:4f)
0x00020a12:50:	*(ram,u0x00006c00(0x00020a12:ee)) = u0x0008ac00:1(0x00020a10:4c)
0x00020a16:51:	goto Block_10:0x000209fe
Basic Block 8 0x000209fc-0x000209fc
0x000209fc:29:	u0x0002f700:1(0x000209fc:29) = a5(0x000209ee:20) == #0x0
0x000209fc:2a:	goto Block_10:0x000209fe if (u0x0002f700:1(0x000209fc:29) != 0) else Block_9:0x00020a3e
Basic Block 9 0x00020a3e-0x00020a50
0x00020a3e:de:	c0x0c20(0x00020a3e:de) = c0x0c20(0x00020a3e:de) ? c0x0c20(i) ? c0x0c20(0x00020a28:c4)
0x00020a3e:a1:	a2(0x00020a3e:a1) = u0x1000002b(0x00020a50:e0) ? u0x1000005b(0x000209f2:e6) ? u0x1000005b(0x000209f2:e6)
0x00020a3e:9c:	a1(0x00020a3e:9c) = a1(0x00020a48:43) ? a1(i) ? a1(i)
0x00020a3e:97:	a0(0x00020a3e:97) = a0(0x00020a4e:46) ? a0(0x000209c8:c) ? a0(0x00020a28:5e)
0x00020a3e:3f:	a3(0x00020a3e:3f) = vsetvli_e8m1tama(a2(0x00020a3e:a1))
0x00020a42:41:	v1(0x00020a42:41) = vle8_v(a1(0x00020a3e:9c))
0x00020a46:c2:	u0x1000001a(0x00020a46:c2) = - a3(0x00020a3e:3f)
0x00020a46:42:	a2(0x00020a46:42) = a2(0x00020a3e:a1) + u0x1000001a(0x00020a46:c2)(*#0x1)
0x00020a48:43:	a1(0x00020a48:43) = a1(0x00020a3e:9c) + a3(0x00020a3e:3f)(*#0x1)
0x00020a4a:45:	vse8_v(v1(0x00020a42:41),a0(0x00020a3e:97))
0x00020a4e:46:	a0(0x00020a4e:46) = a0(0x00020a3e:97) + a3(0x00020a3e:3f)
0x00020a50:47:	u0x0002f700:1(0x00020a50:47) = a2(0x00020a46:42) != #0x0
0x00020a50:e0:	u0x1000002b(0x00020a50:e0) = a2(0x00020a46:42)
0x00020a50:48:	goto Block_9:0x00020a3e if (u0x0002f700:1(0x00020a50:47) != 0) else Block_10:0x000209fe
Basic Block 10 0x000209fe-0x00020a0e
0x000209fe:c8:	c0x0c20(0x000209fe:c8) = c0x0c20(i) ? c0x0c20(i) ? c0x0c20(0x00020a3e:de)
0x000209fe:ef:	u0x100000a3(0x000209fe:ef) = (cast) a0(i)
0x000209fe:2d:	a3(0x000209fe:2d) = *(ram,u0x100000a3(0x000209fe:ef))
0x00020a00:f0:	u0x100000ab(0x00020a00:f0) = (cast) a0(i)
0x00020a00:2f:	u0x100000b3(0x00020a00:2f) = u0x100000ab(0x00020a00:f0) + #0x8
0x00020a00:f1:	u0x00031000(0x00020a00:f1) = (cast) u0x100000b3(0x00020a00:2f)
0x00020a00:30:	*(ram,u0x00031000(0x00020a00:f1)) = a5(0x000209ee:20)
0x00020a02:31:	a5(0x00020a02:31) = a5(0x000209ee:20) + a3(0x000209fe:2d)(*#0x1)
0x00020a04:34:	*(ram,a5(0x00020a02:31)) = #0x0:1
0x00020a0e:c5:	c0x0c20(0x00020a0e:c5) = c0x0c20(0x000209fe:c8)
0x00020a0e:3d:	return(#0x0)
```

The Pcode shows 17 references to the `vl` CSR as `c0x0c20`.  The puzzle is "What *should* the references be?" and "What Rules will get us there?".

Initial observations:

* If the `vl` CSR is loaded anywhere in this function it is propagated through the function.  That means corrective transforms will likely be
  needed throughout.
* The Pcode `c0x0c20(0x00020a5c:c3) = c0x0c20(i) [] i0x00020a5c:73(free)` *looks* like a Phi node but may be something different
* The Pcode `c0x0c20(0x00020a3e:de) = c0x0c20(0x00020a3e:de) ? c0x0c20(i) ? c0x0c20(0x00020a28:c4)` is self-referential
* The Pcode `u0x1000004b(0x000209e8:e4) = c0x0c20(i)` is the only remotely correct CSR reference in the set

What interim design rules make sense here?

* Don't change anything until we understand ops like `c0x0c20(i) [] i0x00020a5c:73(free)`.
* Don't change anything until we are sure that another Rule won't revert those changes.
* Do resolve the scope of any changes - do we want a plugin Rule triggered by specific ops, a plugin Action transforming the entire
  function at once, or a direct patch to the Heritage actions to special case Phi node creation?
* Limit any changes to specific CSRs.  This adds an explicit connection between SLEIGH language definitions and decompiler plugin code,
  so we should put an explicit lookup of the `vl` register within the `riscv.cc` initialization code.
* Volatile CSRs like `vl`/`c0x0c20` should not be part of any PHI PcodeOp.
    * If `c0x0c20` is an output of a PHI PcodeOp, that op should be deleted and any descendant ops be trimmed.
    * If `c0x0c20` is an input of a PHI PcodeOp, that input slot should be removed
    * If `c0x0c20` is cast to a temporary Varnode, then that temporary Varnode is treated like `c0x0c20`.

#### CPUI_INDIRECT

The Decompiler source code suggests that `c0x0c20(0x00020a28:c4) = c0x0c20(i) [] i0x00020a28:5e(free)` is not a Phi or MULTIEQUAL opcode
but a `CPUI_INDIRECT` opcode, described as a "Copy with an indirect effect".  These appear to be used before function calls which *might*
be making changes to the CSR.

#### Rules and Actions

The Decompiler source suggests we want to apply any CSR fixes as an `Action`, not a `Rule`, applied sometime after `ActionHeritage` and before
the `stackstall` group of Rules we currently extend.  The `ActionSpacebase` code is located in about the right place, and suggests a fairly
simple structure.  This suggests generalizing the plugin to add two new `Action` insertion points:
1. At the beginning of `stackstall`, immediately before invoking `oppool1` (which contains our vector rules)
2. within `stackstall`, immediately after invoking `oppool1`

#### Path forward

Let's try a local test to see if we can get this integration test to pass.  Edit the function data once:
1. delete any `CPUI_INDIRECT` or `CPUI_MULTIEQUAL` PcodeOps whose output is `c0x0c20`
2. delete any opcodes like  `u0x1000004b(0x000209e8:e4) = c0x0c20(i)`, following the descendents to replace any reference
   to `u0x1000004b(0x000209e8:e4)` with `c0x0c20(i)`.

This should be structured as a new `Action` to run before `RuleVectorTransform`.  For now, structure it as a new `Rule` to run
before `RuleVectorTransform` and process the entire function on first call.  It will never run on subsequent calls.

### Debugging free node failures

This is an odd puzzle, as the puzzle is also the solution.  By documenting the puzzle carefully you
can find the solution.

The starting point is an integration test failure after what should have been routine refactoring.

```console
github/ghidra_decompiler_plugins$ ./integrationTest.py
INFO:root:Cleaning the executable directory /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/
INFO:root:Running rm -f /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile
INFO:root:Running rm -f /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest
INFO:root:Running bazel build -c opt @ghidra//:decompile
INFO:root:Running bazel build -c dbg @ghidra//:decompile_datatest
.INFO:root:Removing any previous plugin
INFO:root:Running rm -f /tmp/libriscv_vector.so
INFO:root:Building and installing the plugin
INFO:root:Running bazel build -c dbg plugins:riscv_vector
.INFO:root:Running SLEIGHHOME=/opt/ghidra_12.1_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so valgrind /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/memcpy_exemplars.ghidra
found 5 instances of vector_memcpy in test case memcpy_exemplars
.INFO:root:Running SLEIGHHOME=/opt/ghidra_12.1_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_main.ghidra with output to /tmp/whisper_main.testlog
EINFO:root:Running SLEIGHHOME=/opt/ghidra_12.1_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_sample_1a.ghidra with output to /tmp/whisper_sample_1a.testlog
...
SLEIGHHOME=/opt/ghidra_12.1_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_sample_4.ghidra with output to /tmp/whisper_sample_4.testlog
F...
======================================================================
ERROR: test_02_whisper_selection_main_function (__main__.T1Datatests.test_02_whisper_selection_main_function)
Verify correct behavior with the main function of whisper-cpp
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/thixotropist/projects/github/ghidra_decompiler_plugins/./integrationTest.py", line 214, in test_02_whisper_selection_main_function
    result = subprocess.run(command, check=True, capture_output=True,
                            shell=True, encoding="utf8")
  File "/usr/lib64/python3.14/subprocess.py", line 577, in run
    raise CalledProcessError(retcode, process.args,
                             output=stdout, stderr=stderr)
subprocess.CalledProcessError: Command 'SLEIGHHOME=/opt/ghidra_12.1_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_main.ghidra' returned non-zero exit status 134.

======================================================================
FAIL: test_03_application_regression (__main__.T1Datatests.test_03_application_regression)
Verify processing of tests extracted from application functions
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/thixotropist/projects/github/ghidra_decompiler_plugins/./integrationTest.py", line 229, in test_03_application_regression
    run_datatest(self, f"whisper_sample_{i}")
    ~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/thixotropist/projects/github/ghidra_decompiler_plugins/./integrationTest.py", line 105, in run_datatest
    test_case.assertNotIn("Low-level ERROR", result.stdout,
    ~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                     "Decompiler completes without a low level error")
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: 'Low-level ERROR' unexpectedly found in '[decomp]> restore test/whisper_sample_4_save.xml\ntest/whisper_sample_4_save.xml successfully loaded: RISC-V 64 little default\n[decomp]> map function 0xb3824 whisper_model_load\n[decomp]> parse line extern long whisper_model_load(void*, void*);\n[decomp]> load function whisper_model_load\nFunction whisper_model_load: 0x000b3824\n[decomp]> decompile whisper_model_load\nDecompiling whisper_model_load\nLow-level ERROR: Free varnode has multiple descendants\nUnable to proceed with function: whisper_model_load\n[decomp]> print C\nExecution error: No function selected\n[decomp]> print raw\nExecution error: No function selected\n[decomp]> \n' : Decompiler completes without a low level error

----------------------------------------------------------------------
Ran 6 tests in 25.411s

FAILED (failures=1, errors=1)
```
So at least two tests failed, in two different ways.  Both are fairly complex functions from `whisper-cpp`: `main` and `whisper_model_load`

Try running the two tests directly, so we can see the output and optionally run the tests under gdb or valgrind.

```console
github/ghidra_decompiler_plugins$ SLEIGHHOME=/opt/ghidra_12.1_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_main.ghidra
[decomp]> restore test/whisper_main_save.xml
test/whisper_main_save.xml successfully loaded: RISC-V 64 little default
[decomp]> map function 0xbfb30 whisper_init_from_file_with_params
[decomp]> parse line extern long whisper_init_from_file_with_params(void* params);
[decomp]> map function 0x20fd0 main
[decomp]> parse line extern int main(int argc, char** argv);
[decomp]> load function main
Function main: 0x00020fd0
[decomp]> decompile main
Decompiling main
/usr/lib/gcc/x86_64-redhat-linux/15/../../../../include/c++/15/bits/stl_vector.h:1282: std::vector<_Tp, _Alloc>::const_reference std::vector<_Tp, _Alloc>::operator[](size_type) const [with _Tp = ghidra::BlockEdge; _Alloc = std::allocator<ghidra::BlockEdge>; const_reference = const ghidra::BlockEdge&; size_type = long unsigned int]: Assertion '__n < this->size()' failed.
Aborted                    (core dumped) SLEIGHHOME=/opt/ghidra_12.1_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_main.ghidra
```
That's likely an illegal access beyond the last element of a std::vector.  Run it again under `valgrind`:

```console
ghidra_decompiler_plugins$ SLEIGHHOME=/opt/ghidra_12.1_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so valgrind /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_main.ghidra
Decompiling main
/usr/lib/gcc/x86_64-redhat-linux/15/../../../../include/c++/15/bits/stl_vector.h:1282: std::vector<_Tp, _Alloc>::const_reference std::vector<_Tp, _Alloc>::operator[](size_type) const [with _Tp = ghidra::BlockEdge; _Alloc = std::allocator<ghidra::BlockEdge>; const_reference = const ghidra::BlockEdge&; size_type = long unsigned int]: Assertion '__n < this->size()' failed.
==394839==
==394839== Process terminating with default action of signal 6 (SIGABRT): dumping core
==394839==    at 0x4CAD3CC: __pthread_kill_implementation (pthread_kill.c:44)
==394839==    by 0x4C5315D: raise (raise.c:26)
==394839==    by 0x4C3A6CF: abort (abort.c:77)
==394839==    by 0x48AC083: std::__glibcxx_assert_fail(char const*, int, char const*, char const*) (assert_fail.cc:41)
==394839==    by 0xA2F1C1: std::vector<ghidra::BlockEdge, std::allocator<ghidra::BlockEdge> >::operator[](unsigned long) const (stl_vector.h:1282)
==394839==    by 0xA2E13A: ghidra::FlowBlock::getIn(int) const (block.hh:306)
==394839==    by 0xA99173: ghidra::Cover::addRefPoint(ghidra::PcodeOp const*, ghidra::Varnode const*) (cover.cc:607)
==394839==    by 0xBA3F42: ghidra::Merge::eliminateIntersect(ghidra::Varnode*, std::vector<ghidra::BlockVarnode, std::allocator<ghidra::BlockVarnode> > const&) (merge.cc:505)
==394839==    by 0xBA4587: ghidra::Merge::unifyAddress(std::_Rb_tree_const_iterator<ghidra::Varnode*>, std::_Rb_tree_const_iterator<ghidra::Varnode*>) (merge.cc:600)
==394839==    by 0xBA478B: ghidra::Merge::mergeAddrTied() (merge.cc:632)
==394839==    by 0xA830AD: ghidra::ActionMergeRequired::apply(ghidra::Funcdata&) (coreaction.hh:370)
==394839==    by 0xA002CE: ghidra::Action::perform(ghidra::Funcdata&) (action.cc:319)
==394839==
==394839== HEAP SUMMARY:
==394839==     in use at exit: 82,972,872 bytes in 1,481,274 blocks
==394839==   total heap usage: 8,233,756 allocs, 6,752,482 frees, 383,445,322 bytes allocated
==394839==
==394839== LEAK SUMMARY:
==394839==    definitely lost: 24 bytes in 1 blocks
==394839==    indirectly lost: 16 bytes in 1 blocks
==394839==      possibly lost: 2,808 bytes in 1 blocks
==394839==    still reachable: 82,970,024 bytes in 1,481,271 blocks
==394839==                       of which reachable via heuristic:
==394839==                         newarray           : 26,408 bytes in 1 blocks
==394839==         suppressed: 0 bytes in 0 blocks
==394839== Rerun with --leak-check=full to see details of leaked memory
==394839==
==394839== For lists of detected and suppressed errors, rerun with: -s
==394839== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

So the vector access error occured outside of the plugin code, likely because the plugin corrupted the vector of edges flowing into a Block.
Does the plugin log give us any hints?  If you haven't already, make sure the log level is set to `trace` with `pLogger->set_level loglevel(spdlog::level::trace)` in
`riscv.cc`.  If it is something like `spdlog::level::warn`, rebuild the plugin and move it to `/tmp`.

Search backwards from the end of the log (typically something like `/tmp/ghidraRiscvLogger_394839.log` for `error` or `warning` messaging.

```text
[2026-04-06 16:14:33.055] [riscv_vector] [error] PcodeOps with free Varnodes still exist - decompiler will abort:
[2026-04-06 16:14:33.059] [riscv_vector] [warning]      Pcode at 0x2156a:2a1b    = s1(0x00021952:2a19) ? s1(free)
[2026-04-06 16:14:33.059] [riscv_vector] [warning]      Pcode at 0x2156a:7a8c  %0x00000800(0x0002156a:7a8c) = %0x00000800(0x0002150a:7a93) ? %0x00000800(free)
...
[2026-04-06 16:14:33.524] [riscv_vector] [error] PcodeOps with free Varnodes still exist - decompiler will abort:
[2026-04-06 16:14:33.526] [riscv_vector] [warning]      Pcode at 0x21c12:2bb4  a0(0x00021c12:2bb4) = a0(0x00022d24:4ed) ? a0(0x00021bd2:2bc1) ? a0(0x00021bd2:2bc1) ? a0(free)
[2026-04-06 16:14:33.526] [riscv_vector] [warning]      Pcode at 0x21c12:388a  s5(0x00021c12:388a) = s5(0x00022cfc:3888) ? s5(0x00021bf6:4a3) ? s5(0x00021bf6:4a3) ? s5(free)
[2026-04-06 16:14:33.526] [riscv_vector] [warning]      Pcode at 0x21c12:38ba  s6(0x00021c12:38ba) = s0xfffffffffffffab8(0x00021bd2:10269) ? s0xfffffffffffffab8(0x00021bd2:10269) ? s0xfffffffffffffab8(0x00021bd2:10269) ? s6(free)
[2026-04-06 16:14:33.527] [riscv_vector] [warning]      Pcode at 0x21c12:7a7f  %0x00000800(0x00021c12:7a7f) = %0x00000800(0x00022d24:797c) ? %0x00000800(0x00021bd2:7a86) ? %0x00000800(0x00021bd2:7a86) ? %0x00000800(free)
[2026-04-06 16:14:33.527] [riscv_vector] [warning]      Pcode at 0x21c12:1160b  s0xfffffffffffffb38(0x00021c12:1160b) = s0xfffffffffffffb38(0x00022d24:114ef) ? a5(0x00021be2:1b47e) ? a5(0x00021be2:1b47e) ? a0(free)
```

This tells us:
* at two vector transforms of `main` have problems
* the free Varnodes only appear in MULTIEQUAL PcodeOps (multiple Varnodes connected with the '?' character)
* the free Varnodes appear in register address space (e.g, `s1(free)`) and in some address space we haven't seen before (e.g., `%0x00000800(free)`)

That pattern usually means Ghidra is propagating Heritage (aka dependency) analysis on what we believe to be temporary registers assigned during a vector loop.
If it can't prove the register is truly tempory, of if the vector loop sits within an outer loop, this can easily happen.  The usual fix is to simply delete the free Varnode from the
MULTIEQUAL PcodeOp slots, possibly converting the MULTIEQUAL PcodeOp into a COPY op if there is only one Varnode left.

First, we need to verify that this is the case here, starting at the first warning.

What is the history behind `0x2156a:2a1b    = s1(0x00021952:2a19) ? s1(free)`?  `grep` can pull that out of the log

```text
/tmp$ grep 's1(0x0002156a:2a1b)' ghidraRiscvLogger_394839.log
[2026-04-06 16:14:31.988] [riscv_vector] [trace] 	0x2156a: [60] s1(0x0002156a:2a1b) = s1(0x00021952:2a19) ? s1(0x00021552:1b381)
[2026-04-06 16:14:32.907] [riscv_vector] [trace]   Descendent op: s1(0x0002156a:2a1b) = s1(0x00021952:2a19) ? s1(0x00021552:1b381)
[2026-04-06 16:14:32.913] [riscv_vector] [trace] Examining context of: s1(0x0002156a:2a1b) = s1(0x00021952:2a19) ? s1(0x00021552:1b381)
[2026-04-06 16:14:32.913] [riscv_vector] [trace]   exterior dependency to fix: s1(0x0002156a:2a1b)
[2026-04-06 16:14:33.059] [riscv_vector] [warning] 	Pcode at 0x2156a:2a1b  s1(0x0002156a:2a1b) = s1(0x00021952:2a19) ? s1(free)
```

The original Pcode included `s1(0x0002156a:2a1b) = s1(0x00021952:2a19) ? s1(0x00021552:1b381)` which our plugin changed to
`s1(0x0002156a:2a1b) = s1(0x00021952:2a19) ? s1(free)`, probably by deleting `s1(0x00021552:1b381)`.  The vector summaries report file
tells us that 0x00021552 is the start of a `vector_memcpy` loop, which is where you would expect to find multiple MULTIEQUAL PcodeOps.

What does the log file say about `s1(0x00021552:1b381)`?

```text
[2026-04-06 16:14:32.944] [riscv_vector] [info] Deleting PcodeOp  at 0x21552:1b381
[2026-04-06 16:14:32.945] [riscv_vector] [info]         Note Descendent PcodeOp  at 0x21552:1b381
[2026-04-06 16:14:32.945] [riscv_vector] [info]         Note Descendent PcodeOp  at 0x2156a:2a1b
[2026-04-06 16:14:32.945] [riscv_vector] [info] Preparing to edit the flow block graph to remove the loop edge
...
```

So that's the first thing to fix: add some cleanup code such that any remaining Varnode flagged with 'Note Descendent PcodeOp  at' is
pruned out of descendent MULTIEQUAL nodes.  That will likely mean added code near the end of `FunctionEditor::simplifyBlocks`, looping over
the Varnodes in `descendentsToReview`, and adding a new method to remove any `free` varnodes.

>Note: Varnodes like `%0x00000800(0x0002156a:7a8c)` have something to do with memory references.  That's a new puzzle to log and pursue later.

Add and debug some supporting code, and try the integration test again.  The specific test whisper_sample_4 now passes, allowing the test case to
advance to whisper_sample_5, which fails with an error similar to the whisper_main error.

>Note: deleting a PcodeOp more than once is a common error, as is trimming a MULTIEQUAL PcodeOp down to a single slot.

Continue with the error logs from whisper_sample_5:

```text
Possible Epilog Pcode: s2(0x000b9d64:52c) = s2(0x000b9c94:4bd) + a5(0x000b9d50:2436)
...
Basic Block 129 0x000b9d50-0x000b9d62
0x000b9d50:2436:        a5(0x000b9d50:2436) = a5(0x000b9d50:2436) ? a5(0x000b9d48:51f) ? s10(0x000b9cfa:1208)
0x000b9d50:113a:        a6(0x000b9d50:113a) = a6(0x000b9d60:529) ? a5(0x000b9d48:51f) ? s10(0x000b9cfa:1208)
0x000b9d50:ead: a0(0x000b9d50:ead) = a0(0x000b9d58:525) ? s2(0x000b9c94:4bd) ? s2(0x000b9c94:4bd)
0x000b9d50:e6a: s1(0x000b9d50:e6a) = s1(0x000b9d5a:526) ? s1(0x000b9c7c:2448) ? s1(0x000b9c7c:2448)
0x000b9d50:522: a4(0x000b9d50:522) = vsetvli_e8m1tama(a0(0x000b9d50:ead))
0x000b9d54:524: v1(0x000b9d54:524) = vle8_v(s1(0x000b9d50:e6a))
0x000b9d58:134b:        u0x1000020d(0x000b9d58:134b) = a4(0x000b9d50:522) * #0xffffffffffffffff
0x000b9d58:525: a0(0x000b9d58:525) = a0(0x000b9d50:ead) + u0x1000020d(0x000b9d58:134b)
0x000b9d5a:526: s1(0x000b9d5a:526) = s1(0x000b9d50:e6a) + a4(0x000b9d50:522)
0x000b9d5c:528: vse8_v(v1(0x000b9d54:524),a6(0x000b9d50:113a))
0x000b9d60:529: a6(0x000b9d60:529) = a6(0x000b9d50:113a) + a4(0x000b9d50:522)
0x000b9d62:52a: u0x0002f700:1(0x000b9d62:52a) = a0(0x000b9d58:525) != #0x0
0x000b9d62:52b: goto Block_129:0x000b9d50 if (u0x0002f700:1(0x000b9d62:52a) != 0) else Block_130:0x000b9d64

[2026-04-07 14:41:59.315] [riscv_vector] [info] Transforming selection into vector_memcpy
[2026-04-07 14:41:59.315] [riscv_vector] [info]         Inserting a new vector operation
                syscall[#0x11000001:4](a5(0x000b9d48:51f),s1(0x000b9c7c:2448),s2(0x000b9c94:4bd))
[2026-04-07 14:41:59.315] [riscv_vector] [info] Deleting PcodeOp  at 0xb9d50:2436
[2026-04-07 14:41:59.315] [riscv_vector] [info]         Note Descendent PcodeOp  at 0xb9d50:2436
...
Basic Block 129 0x000b9d50-0x000b9d62
0x000b9d62:2496:        vector_memcpy(a5(0x000b9d48:51f),s1(0x000b9c7c:2448),s2(0x000b9c94:4bd))
Basic Block 130 0x000b9d64-0x000b9d68
0x000b9d64:52c: s2(0x000b9d64:52c) = s2(0x000b9c94:4bd) + a5(free)
...
[2026-04-07 14:41:59.341] [riscv_vector] [error] PcodeOps with free Varnodes still exist - decompiler will abort:
[2026-04-07 14:41:59.343] [riscv_vector] [warning]      Pcode at 0xb9d64:52c  s2(0x000b9d64:52c) = s2(0x000b9c94:4bd) + a5(free)
```

Work through this from the bottom up:
* The segfault triggers due to `a5(free)` in `s2(0x000b9d64:52c) = s2(0x000b9c94:4bd) + a5(free)`
* Before the transform that PcodeOp was `s2(0x000b9d64:52c) = s2(0x000b9c94:4bd) + a5(0x000b9d50:2436)`, so we deleted the Pcode op setting `a5(0x000b9d50:2436)`
  too aggressively.
* That deleted PcodeOp was `a5(0x000b9d50:2436) = a5(0x000b9d50:2436) ? a5(0x000b9d48:51f) ? s10(0x000b9cfa:1208)`. It begins a `vector_memset` Block
  but isn't itself a part of the `vector_memset` transform - it simply passes a register heritage to the two subsequent blocks.

The log file provides more hints.  Extraneous lines are silently deleted.

```text
Entering applyOp with a recognized vset* user pcode op at 0xb9d50 // entry point for analysis of this vector stanza
Iterating over vset phi pcodes
Analysis of Phi node: s1(0x000b9d50:e6a) = s1(0x000b9d5a:526) ? s1(0x000b9c7c:2448) ? s1(0x000b9c7c:2448)
Analysis of Phi node: a0(0x000b9d50:ead) = a0(0x000b9d58:525) ? s2(0x000b9c94:4bd) ? s2(0x000b9c94:4bd)
Analysis of Phi node: a6(0x000b9d50:113a) = a6(0x000b9d60:529) ? a5(0x000b9d48:51f) ? s10(0x000b9cfa:1208)
Analysis of Phi node: a5(0x000b9d50:2436) = a5(0x000b9d50:2436) ? a5(0x000b9d48:51f) ? s10(0x000b9cfa:1208)
Found 4 Phi nodes affected by the loop
Beginning loop pcode analysis
PcodeOp at 0xb9d50: a5(0x000b9d50:2436) = a5(0x000b9d50:2436) ? a5(0x000b9d48:51f) ? s10(0x000b9cfa:1208)
PcodeOp at 0xb9d50: a6(0x000b9d50:113a) = a6(0x000b9d60:529) ? a5(0x000b9d48:51f) ? s10(0x000b9cfa:1208)
PcodeOp at 0xb9d50: a0(0x000b9d50:ead) = a0(0x000b9d58:525) ? s2(0x000b9c94:4bd) ? s2(0x000b9c94:4bd)
PcodeOp at 0xb9d50: s1(0x000b9d50:e6a) = s1(0x000b9d5a:526) ? s1(0x000b9c7c:2448) ? s1(0x000b9c7c:2448)
PcodeOp at 0xb9d50: a4(0x000b9d50:522) = vsetvli_e8m1tama(a0(0x000b9d50:ead))
PcodeOp at 0xb9d54: v1(0x000b9d54:524) = vle8_v(s1(0x000b9d50:e6a))
PcodeOp at 0xb9d58: u0x1000020d(0x000b9d58:134b) = a4(0x000b9d50:522) * #0xffffffffffffffff
PcodeOp at 0xb9d58: a0(0x000b9d58:525) = a0(0x000b9d50:ead) + u0x1000020d(0x000b9d58:134b)
PcodeOp at 0xb9d5a: s1(0x000b9d5a:526) = s1(0x000b9d50:e6a) + a4(0x000b9d50:522)
PcodeOp at 0xb9d5c: vse8_v(v1(0x000b9d54:524),a6(0x000b9d50:113a))
PcodeOp at 0xb9d60: a6(0x000b9d60:529) = a6(0x000b9d50:113a) + a4(0x000b9d50:522)
PcodeOp at 0xb9d62: u0x0002f700:1(0x000b9d62:52a) = a0(0x000b9d58:525) != #0x0
PcodeOp at 0xb9d62: goto Block_129:0x000b9d50 if (u0x0002f700:1(0x000b9d62:52a) != 0) else Block_130:0x000b9d64
Possible Epilog Pcode: s2(0x000b9d64:52c) = s2(0x000b9c94:4bd) + a5(0x000b9d50:2436)
Tracing loop dependencies for register result a5 with register offset 0x2078
   inloop dependency: a5(0x000b9d50:2436)
   Descendent op: a5(0x000b9d50:2436) = a5(0x000b9d50:2436) ? a5(0x000b9d48:51f) ? s10(0x000b9cfa:1208)
   Descendent op: s2(0x000b9d64:52c) = s2(0x000b9c94:4bd) + a5(0x000b9d50:2436)
```

Notes:
* register `a6` is a true in-loop dependency because it is evolves as the destination pointer for the vse8 instruction.
* register `a6` is the output of a MULTIEQUAL PcodeOp referencing register `a5(0x000b9d48:51f)`, a Varnode set outside of the loop.
* register `a5` is not used as a temporary register within the loop, even though its MULTIEQUAL PcodeOp appears within the loop block.

So there are only three MULTIEQUAL PcodeOps 'affected by the loop', even though there are four MULTIEQUAL PcodeOps 'within the loop'.

The current source code only checks if the MULTIEQUAL op is within the loop:

```c
ghidra::intb offset = definingOp->getAddr().getOffset();
if ((offset >= firstAddr) && (offset <= lastAddr))
    phiNodesAffectedByLoop.push_back(op);
```

The simple fix for this `vector_memcpy` stanza unfortunately breaks transforms of other `vector_strlen` stanzas.
We need to do a better job of defining the relationship between related sets:

* the original `phiNodesAffectedByLoop`
* Phi nodes unrelated to the vector loop that are located within the loop Block.  These must be preserved, never deleted.
* Phi nodes needed to establish a linkage between temporary register variables used within the loop
* Phi nodes that can be safely deleted during a transform
* Phi nodes that have unresolved dependencies outside of the loop that block any transform
* Phi nodes that have resolved descendents of temporary loop epilog registers

### Phi nodes and vector Control and Status Registers

Some MULTIEQUAL PCodeOps refer to Control and Status registers
