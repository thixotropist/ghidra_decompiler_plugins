---
title: Plugin Development Example
description: Plugin development is likely driven by a particularly confusing class of executable binaries
weight: 40
---

Vector instructions commonly appear in surprising places.  Let's generate a Ghidra decompiler plugin that
recognizes some of the simplest vector sequences and replaces them with something more user-friendly.
Initialization code often initializes stack variables with default values.  If the compiler sees two adjacent
8 bit variables or fields initialized from adjacent sources, it can issue two pairs of 8 bit loads and stores.  It can't generally
issue a single 16 bit load and store, due to memory alignment restrictions on many processors.  But it can issue three vector instructions to complete
the initialization, saving one instruction slot.  This example shows the development sequence for a plugin to transform that kind
of vector sequence into a call to `builtin_memcpy`, something that should be a lot more accessible to most Ghidra users than
RISC-V vector instruction encodings.  Along the way we will add a new builtin function `builtin_memset`, as the patterns can be quite similar.

## Building a test

The first step is to generate a sample of the raw binary sequence we want to transform, then wrap it in the style the Ghidra decompiler
console interface can work with.  We definitely don't want to have to rebuild Ghidra or the decompiler itself on every iteration of development.
Ghidra's decompiler supports this natively, providing a console-driven version of the decompiler and a data test framework.  A data test provides a short
byte sequence, a processor/language description, function signature, basic type definitions, and decompiler output assertions.

A good example of an existing Ghidra decompiler data test is `Ghidra/Features/Decompiler/src/decompile/datatests/heapstring.xml` from the Ghidra source
repo.  This test verifies that the `RuleStringCopy` class of `constseq.cc` is correctly transforming sequences of x86_64 loads and stores into a single
call to `builtin_memcpy`.  That's almost exactly what we want to do for RISC-V vector loads and stores.

`heapstring.xml` has these elements:

```xml
<decompilertest>
    <binaryimage arch="x86:LE:64:default:gcc">
        <bytechunk space="ram" offset="0x100000" readonly="true">
            f30f1efa48ba4d6573736167653a488b
            07488910c6400820c3
        </bytechunk>
    <symbol space="ram" offset="0x100000" name="fillin"/>
    </binaryimage>
    <script>
        <com>option readonly on</com>
        <com>parse line extern void fillin(mystring *ptr);</com>
        <com>load function fillin</com>
        <com>decompile</com>
    </script>
    <stringmatch name="Heap string #1" min="1" max="1">builtin_strncpy\(ptr-\>val,"Message: ",9\);</stringmatch>
</decompilertest>
```

We will first want something less structured than a set of assertions, since we will want lots of survey and diagnostic
information during development.  The `xml_savefile` element lets us capture the bytes and type information in one file,
with decompiler commands separated in a different script.

`test/memcpy_exemplars_save.xml` describes the input we want.

```xml
<xml_savefile name="main" target="default" adjustvma="0">
    <binaryimage arch="RISCV:LE:64:RV64GC">
        <bytechunk space="ram" offset="0x0" readonly="true">
            577051cc87800502a700050282805770
            62cc01000100878005020100a7000502
            8280577074cc01000100878005020100
            a7000502828057f007cc878005020100
            0100a70005028280d776060c87800502
            158e3695a7000502b6957df682805a00
        </bytechunk>
    </binaryimage>
    <coretypes>
        <void />
        <type name="uint" size="4" metatype="uint" id="-9223371465083307041" />
        <type name="code" size="1" metatype="code" id="-9223371462259126427" />
        <type name="int" size="4" metatype="int" id="-9223370945157383201" />
        <type name="uint3" size="3" metatype="uint" id="-9223225663358771405" />
        <type name="uint5" size="5" metatype="uint" id="-9223225663358771403" />
        <type name="uint7" size="7" metatype="uint" id="-9223225663358771401" />
        <type name="uint6" size="6" metatype="uint" id="-9223225661105102435" />
        <type name="int3" size="3" metatype="int" id="-9223092562322268365" />
        <type name="int5" size="5" metatype="int" id="-9223092562322268363" />
        <type name="int7" size="7" metatype="int" id="-9223092562322268361" />
        <type name="int6" size="6" metatype="int" id="-9223092560068599395" />
        <type name="char" size="1" metatype="int" char="true" id="-9223091865880322087" />
        <type name="uint16" size="16" metatype="uint" id="-9185900419569365091" />
        <type name="ushort" size="2" metatype="uint" id="-9185691276929259553" />
        <type name="int16" size="16" metatype="int" id="-9151826554224586851" />
        <type name="byte" size="1" metatype="uint" id="-9151688846347870363" />
        <type name="long" size="8" metatype="int" id="-9151688846179449497" />
        <type name="bool" size="1" metatype="bool" id="-9151688804115639865" />
        <type name="sbyte" size="1" metatype="int" id="-9151648198777381019" />
        <type name="short" size="2" metatype="int" id="-9151648197910059041" />
        <type name="ulong" size="8" metatype="uint" id="-9151648190019025561" />
        <type name="wchar_t" size="4" metatype="int" utf="true" id="-8801050271826140705" />
        <type name="wchar16" size="2" metatype="int" utf="true" id="-8801050271826128995" />
        <type name="double" size="8" metatype="float" id="-6087405195602966429" />
        <type name="float10" size="10" metatype="float" id="-5894303970639204475" />
        <type name="undefined" size="1" metatype="unknown" id="-4223139060020122321" />
        <type name="float2" size="2" metatype="float" id="-3085472373819564389" />
        <type name="undefined2" size="2" metatype="unknown" id="-1989071053142544393" />
        <type name="undefined4" size="4" metatype="unknown" id="-1989071053142544391" />
        <type name="undefined6" size="6" metatype="unknown" id="-1989071053142544389" />
        <type name="undefined8" size="8" metatype="unknown" id="-1989071053142544387" />
        <type name="undefined5" size="5" metatype="unknown" id="-1989071052499136175" />
        <type name="undefined3" size="3" metatype="unknown" id="-1989071052499136173" />
        <type name="undefined7" size="7" metatype="unknown" id="-1989071052499136169" />
        <type name="undefined1" size="1" metatype="unknown" id="-1989071052499136163" />
        <type name="longdouble" size="16" metatype="float" id="-1267909053971395201" />
        <type name="float" size="4" metatype="float" id="-120139017508053025" />
    </coretypes>
</xml_savefile>
```

The decompiler commands are now in a script file, `test/memcpy_exemplars.ghidra`:

```text
restore test/memcpy_exemplars_save.xml
map function 0x00000 memcpy_i2
map function 0x0000e memcpy_i4
map function 0x00022 memcpy_i8
map function 0x00036 memcpy_i15
map function 0x00048 memcpy_v1
parse line extern void memcpy_i2(void* to, void* from, long size);
parse line extern void memcpy_i4(void* to, void* from, long size);
parse line extern void memcpy_i8(void* to, void* from, long size);
parse line extern void memcpy_i15(void* to, void* from, long size);
parse line extern void memcpy_v1(void* to, void* from, long size);
load function memcpy_i2
decompile memcpy_i2
print C
print raw
load function memcpy_i4
decompile memcpy_i4
print C
print raw
load function memcpy_i8
decompile memcpy_i8
print C
print raw
load function memcpy_i15
decompile memcpy_i15
print C
print raw
load function memcpy_v1
decompile memcpy_v1
print C
print raw
```

That shows the kind of input files we need, so now we need to show where the instruction bytes to be inserted into
`bytechunk` come from.  Generate a RISC-V assembly source file capturing some of the sequences we want to transform.
This file shows a simplified form of vector sequences generated by gcc's `_builtin_memcpy` function, for various
constant and variable size values.

`test/memcpy_exemplars.S`:

```as
# collect vector sequences we would like to see transformed into builtin_memcpy calls
# source:  whisper.cpp built with O3, fast-math, and r64gcv

.section .text

# copy fixed 2 bytes
.extern memcpy_i2
memcpy_i2:
    vsetivli zero,0x2,e8,mf8,ta,ma 
    vle8.v   v1,(a1)
    vse8.v   v1,(a0)
    ret

# copy fixed 4 bytes
.extern memcpy_i4
memcpy_i4:
    vsetivli  zero,0x4,e8,mf4,ta,ma 
    nop
    nop
    vle8.v    v1,(a1)
    nop
    vse8.v    v1,(a0)
    ret

# copy fixed 8 bytes
.extern memcpy_i8
memcpy_i8:
    vsetivli  zero,0x8,e8,mf2,ta,ma 
    nop
    nop
    vle8.v    v1,(a1)
    nop
    vse8.v    v1,(a0)
    ret

# copy fixed 15 bytes
.extern memcpy_i15
memcpy_i15:
    vsetivli zero,0xf,e8,m1,ta,ma  
    vle8.v   v1,(a1)
    nop
    nop
    vse8.v   v1,(a0)
    ret

# copy variable
.extern memcpy_v1
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

We want to assemble this into a single binary file `memcpy_exemplars.so`.  This Makefile stanza will work.

```make
CC:=/opt/riscv/sysroot/bin/riscv64-unknown-linux-gnu-g++

memcpy_exemplars.so: memcpy_exemplars.S
        $(CC) -march=rv64gcv -o $@ -c $<
```

Import `memcpy_exemplars.so` into Ghidra, then export the project as XML.  You should get a pure binary
file `memcpy_exemplars.so.bytes`.  We need those bytes as ASCII, so execute `hexdump -X memcpy_exemplars.so.bytes > tmp.bytes`.
A little editing of `tmp.bytes` will give you something you can insert into a `bytechunk` element.

Now we can run our control experiment, pushing our sample of memcpy vector sequences through the unmodified Ghidra decompiler.
We'll do all of this under valgrind control, just to get into the habit of worrying about object lifetime.

```console
$ SLEIGHHOME=/opt/ghidra_11.4_DEV/ \
> valgrind /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/memcpy_exemplars.ghidra
==75773== Memcheck, a memory error detector
==75773== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==75773== Using Valgrind-3.24.0 and LibVEX; rerun with -h for copyright info
==75773== Command: /home/thixotropist/projects/github/ghidra_transforms/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/decomp_dbg
==75773== 
[decomp]> restore test/memcpy_exemplars_save.xml
test/memcpy_exemplars_save.xml successfully loaded: RISC-V 64 little general purpose compressed
[decomp]> map function 0x00000 memcpy_i2
[decomp]> map function 0x0000e memcpy_i4
[decomp]> map function 0x00022 memcpy_i8
[decomp]> map function 0x00036 memcpy_i15
[decomp]> map function 0x00048 memcpy_v1
[decomp]> parse line extern void memcpy_i2(void* to, void* from, long size);
[decomp]> parse line extern void memcpy_i4(void* to, void* from, long size);
[decomp]> parse line extern void memcpy_i8(void* to, void* from, long size);
[decomp]> parse line extern void memcpy_i15(void* to, void* from, long size);
[decomp]> parse line extern void memcpy_v1(void* to, void* from, long size);
[decomp]> load function memcpy_i2
Function memcpy_i2: 0x00000000
[decomp]> decompile memcpy_i2
Decompiling memcpy_i2
Decompilation complete
[decomp]> print C

void memcpy_i2(void *to,void *from,long size)

{
  undefined auVar1 [256];
  vsetivli_e8mf8tama(2);
  auVar1 = vle8_v(from);
  vse8_v(auVar1,to);
  return;
}
[decomp]> print raw
0
Basic Block 0 0x00000000-0x0000000c
0x00000000:1:	vsetivli_e8mf8tama(#0x2:5)
0x00000004:3:	v1(0x00000004:3) = vle8_v(a1(i))
0x00000008:5:	vse8_v(v1(0x00000004:3),a0(i))
0x0000000c:6:	return(#0x0)
[decomp]> load function memcpy_i4
Function memcpy_i4: 0x0000000e
[decomp]> decompile memcpy_i4
Decompiling memcpy_i4
Decompilation complete
[decomp]> print C

void memcpy_i4(void *to,void *from,long size)

{
  undefined auVar1 [256];
  vsetivli_e8mf4tama(4);
  auVar1 = vle8_v(from);
  vse8_v(auVar1,to);
  return;
}
[decomp]> print raw
0
Basic Block 0 0x0000000e-0x00000020
0x0000000e:1:	vsetivli_e8mf4tama(#0x4:5)
0x00000016:7:	v1(0x00000016:7) = vle8_v(a1(i))
0x0000001c:b:	vse8_v(v1(0x00000016:7),a0(i))
0x00000020:c:	return(#0x0)
[decomp]> load function memcpy_i8
Function memcpy_i8: 0x00000022
[decomp]> decompile memcpy_i8
Decompiling memcpy_i8
Decompilation complete
[decomp]> print C

void memcpy_i8(void *to,void *from,long size)

{
  undefined auVar1 [256];
  vsetivli_e8mf2tama(8);
  auVar1 = vle8_v(from);
  vse8_v(auVar1,to);
  return;
}
[decomp]> print raw
0
Basic Block 0 0x00000022-0x00000034
0x00000022:1:	vsetivli_e8mf2tama(#0x8:5)
0x0000002a:7:	v1(0x0000002a:7) = vle8_v(a1(i))
0x00000030:b:	vse8_v(v1(0x0000002a:7),a0(i))
0x00000034:c:	return(#0x0)
[decomp]> load function memcpy_i15
Function memcpy_i15: 0x00000036
[decomp]> decompile memcpy_i15
Decompiling memcpy_i15
Decompilation complete
[decomp]> print C

void memcpy_i15(void *to,void *from,long size)

{
  undefined auVar1 [256];
  vsetivli_e8m1tama(0xf);
  auVar1 = vle8_v(from);
  vse8_v(auVar1,to);
  return;
}
[decomp]> print raw
0
Basic Block 0 0x00000036-0x00000046
0x00000036:1:	vsetivli_e8m1tama(#0xf:5)
0x0000003a:3:	v1(0x0000003a:3) = vle8_v(a1(i))
0x00000042:9:	vse8_v(v1(0x0000003a:3),a0(i))
0x00000046:a:	return(#0x0)
[decomp]> load function memcpy_v1
Function memcpy_v1: 0x00000048
[decomp]> decompile memcpy_v1
Decompiling memcpy_v1
Decompilation complete
[decomp]> print C

void memcpy_v1(void *to,void *from,ulong size)

{
  long lVar1;
  undefined auVar2 [256];
  
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
[decomp]> print raw
0
Basic Block 0 0x00000048-0x00000048
Basic Block 1 0x00000048-0x0000005a
0x00000048:e:	a2(0x00000048:e) = a2(0x00000050:3) ? a2(i)
0x00000048:d:	a1(0x00000048:d) = a1(0x00000058:15) ? a1(i)
0x00000048:c:	a0(0x00000048:c) = a0(0x00000052:13) ? a0(i)
0x00000048:0:	a3(0x00000048:0) = vsetvli_e8m1tama(a2(0x00000048:e))
0x0000004c:2:	v1(0x0000004c:2) = vle8_v(a1(0x00000048:d))
0x00000050:3:	a2(0x00000050:3) = a2(0x00000048:e) - a3(0x00000048:0)
0x00000052:12:	u0x10000008(0x00000052:12) = (cast) a0(0x00000048:c)
0x00000052:4:	u0x10000010(0x00000052:4) = u0x10000008(0x00000052:12) + a3(0x00000048:0)
0x00000052:13:	a0(0x00000052:13) = (cast) u0x10000010(0x00000052:4)
0x00000054:6:	vse8_v(v1(0x0000004c:2),a0(0x00000052:13))
0x00000058:14:	u0x10000018(0x00000058:14) = (cast) a1(0x00000048:d)
0x00000058:7:	u0x10000020(0x00000058:7) = u0x10000018(0x00000058:14) + a3(0x00000048:0)
0x00000058:15:	a1(0x00000058:15) = (cast) u0x10000020(0x00000058:7)
0x0000005a:8:	u0x00018500:1(0x0000005a:8) = a2(0x00000050:3) != #0x0
0x0000005a:9:	goto r0x00000048:1(free) if (u0x00018500:1(0x0000005a:8) != 0)
Basic Block 2 0x0000005c-0x0000005c
0x0000005c:a:	return(#0x0)
[decomp]> 
==75773== 
==75773== HEAP SUMMARY:
==75773==     in use at exit: 0 bytes in 0 blocks
==75773==   total heap usage: 227,449 allocs, 227,449 frees, 21,201,502 bytes allocated
==75773== 
==75773== All heap blocks were freed -- no leaks are possible
==75773== 
==75773== For lists of detected and suppressed errors, rerun with: -s
==75773== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

So that control experiment looks good.  The vector instructions are recognized and the decompiler
turns out recognizable C-like source code matching what we would have seen in the Ghidra decompiler window.
There are no memory leaks and no segfaults.

The `print raw` output shows us what our new rule plugin will be working with.  For example,
the function copying 15 bytes decompiles as:

```c
void memcpy_i15(void *to,void *from,long size)
{
  undefined auVar1 [256];
  vsetivli_e8m1tama(0xf);
  auVar1 = vle8_v(from);
  vse8_v(auVar1,to);
  return;
}
```
Its raw form is:

```text
Basic Block 0 0x00000036-0x00000046
0x00000036:1:	vsetivli_e8m1tama(#0xf:5)
0x0000003a:3:	v1(0x0000003a:3) = vle8_v(a1(i))
0x00000042:9:	vse8_v(v1(0x0000003a:3),a0(i))
0x00000046:a:	return(#0x0)
```

Our plugin should rewrite the pcode ops and varnodes to turn the raw form into something like:

```text
Basic Block 0 0x00000036-0x00000046
0x00000036:1:	vector_memcpy(a0(i), a1(i), #0xf:5)
0x00000046:a:	return(#0x0)
```

That doesn't look too hard, once we understand some of the internal rules for PcodeOps and Varnodes.

The more complicated test case is the last one, where the number of bytes to copy is unknown to the
compiler and a loop must be generated.  Figuring out Varnode lifetimes around a loop, then how to
delete the loop and merge Basic Blocks, is something to sort out a bit later.

## Decompiler hooks and the PluginManager

Now that we have an initial test and a desired result we can figure out how the new plugin should work.
That breaks down into several survey steps:

1. Understand what code enables the existing `heapstring` transform test.
    * This appears to center on the `constseq.*` decompiler files, several new
      `RuleString*` classes derived from `Rule`, and some support classes like `ArraySequence`.
      Various `transform` methods complete the transformation of load/store sequences.
      into a `builtin_memcpy` call.
2.  Review how the existing code validates potential sequences to transform.
    * This appears to involve overloading `Rule::applyOp` to request a callback
      for every instance of a set of pcodeops, plus a complicated traversal
      of pcode ops and Varnodes to match a sequence to be transformed.
3. Establish how the `RuleString*` classes are registered within the set of decompiler Actions.
    * This appears to be done in `coreaction.cc` by instantiating the new Rules and
      adding them to the `cleanup` group of the decompiler's `ActionDatabase`.
4. Determine how `RuleString*` methods fit into the overall workflow of the decompiler.
    * Individual `cleanup` rules are applied repeatedly during the cleanup phase until
      they all return a 0 value, indicating that no further changes have been made.
      This implies that our new rules may see the same raw sequences many times, before
      and after other rules have made their transforms.
5. Explore the lifetime rules and consistency checks that apply when creating and deleting
   Rules, PcodeOps, and Varnodes.
    * The lifetimes of Rules and Architectures is unclear, especially as Rules created by
      a plugin may be cloned, with their clones surviving the destruction of the creating
      Architecture.  This implies we don't know when we can safely unload a plugin, as unloading
      a plugin will unmap any Rule destructor code and so force a segfault on exit.
    * This will only become clear with trial and error - and a lot of segfaults. Further research
      into Varnode descendent lists and Indirect varnodes looks to be essential.
6. Explore the top level Ghidra decompiler classes to find a home for the new `PluginManager`.
   Ideally we want something that gets initialized in both console and GUI decompiler variants,
   and which holds lots of useful context information like the `ActionDatabase`.
    * The `Architecture` class looks like a good bet, as that appears to hold the memory image
      being analyzed, the `ActionDatabase`, and some information on the processor specification.
    * The first `PluginManager` iteration will then be owned by `Architecture` and initialized just
      before the default or universal action groups are initialized in `ActionDatabase`.  The
      `PluginManager` object will use `dlopen` to load a single plugin named in an environment
      variable, initialize the plugin, and give the plugin the chance to add new Rules and builtin functions.
    * Patch `ActionDatabase::universalAction` to add those new Rules from `PluginManager` just after
      the `constsequence` rules are added to the cleanup group.
    * Establish a basic logging output stream for use during debugging.  We could use `std::cout` for
      the console version of the decompiler, but that won't work for the Ghidra client version of the
      decompiler as std::cout is needed for the socket to the Ghidra Java GUI.  We'll add [spdlog](https://github.com/gabime/spdlog)spdlog
      support to the decompiler, where it can be used by both the PluginManager and individual plugins.

>Note: `vector_memcpy` is different from a `builtin_memcpy` or `memcpy` in that it returns void instead of the address of
       the destination parameter 

## Plugin specifics

The sample plugin (currently) consists of three components:

* `plugins/riscv.cc` provides
    * Entry points called by the plugin manager, such as `plugin_init` and `plugin_getrules`
    * One or more std::vector collections of instruction names we may want to track.
      This includes vector instruction names like `vsetivli_e8m1tama`.
    * A shared `std::map` of vector instruction names to `UserPcodeOp` pointers.  This map is
      constructed after plugin loading from the SLEIGH definitions provided.  The decompiler
      console program retrieves this information from a Ghidra distribution's Processor/* directories.
      The Ghidra decompiler process retrieves this information from the Ghidra GUI's Java implementation.
* `vectorcopy.{hh,cc}` provides the Rules for transforming non-loop vector instruction sequences into
  calls to `vector_memcpy` calls. Provided capabilities include
    * `displayPcodeOp`, `displayVarnode`, and `displayVectorSequence` for diagnostics and survey work.
      These are not used in deployed systems.
    * The `RuleVectorCopy` class implementing the match and transform logic.
    * `RuleVectorCopy::getOpList` registers the intrinsic operations for which a callback is requested.
      All user pcode ops are invoked via the CALLOTHER operation, so we register an interest in
      `CPUI_CALLOTHER`.
    * `RuleVectorCopy::applyOp(PcodeOp *op, Funcdata &data)` does the work.  The `op` parameter gives
      the specific `CPUI_CALLOTHER` PcodeOp found.  The `data` parameter gives the function in which
      this PcodeOp was found.
* `vector_tree_match.{hh,cc}` provides the logic to analyze and transform loops of vector instructions.

The logic implemented by `RuleVectorCopy::applyOp` follows this flow:

* RISC-V Vector instruction sequences generally start with one of the many `vset*` instructions.
  The SLEIGH files treat these with `define pcodeop ...` rules, which the decompiler captures as
  the `ghidra::UserPcodeOp` class.  These appear to `RuleVectorCopy::applyOp` as a `CPUI_CALLOTHER`
  pcode operation for which the first `Varnode` parameter identifies the specific SLEIGH pcodeop.
  Up to three more input Varnodes capture the instruction input arguments.  An output Varnode
  holds any output register for the instruction.
* `RuleVectorCopy::applyOp` is then called each time the decompiler visits a CALLOTHER operation.
  If the first Varnode argument is not one of the identified `vset*` instructions, the rule exits
  immediately with a 'no changes' return value of 0.  Otherwise the sequence is checked to
  see if a transform is desirable and safe.
* Once a matching `vset*` user pcode op is identified the next several instructions are examined,
  looking for a vector load instruction followed by a vector store instruction, where the two
  vector instructions reference the same vector register.  Unrelated instructions may appear
  between them, while branch instructions may not.
* If a match is found, a new `builtin_memcpy` PcodeOp is built with the three parameters taken
  exactly from the input varnodes of the three vector instructions.  That new PcodeOp is inserted
  into the function data object passed to `RuleVectorCopy::applyOp`.  The three vector instruction
  PcodeOps are then unlinked from the function data object (FuncData&) data.

## exercising the plugin

Once we have the plugin logic we can build and exercise it.  Bazel will build it, and we'll leave
it in `/tmp`.  We can pass this plugin location with the `DECOMP_PLUGIN` environment variable.

```console
$ bazel build -c dbg plugins:riscv_vector
...
$ cp -f bazel-bin/plugins/libriscv_vector.so /tmp

$ SLEIGHHOME=/opt/ghidra_11.4_DEV/ \
  DECOMP_PLUGIN=/tmp/libriscv_vector.so \
  valgrind /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/memcpy_exemplars.ghidra
...
[decomp]> restore test/memcpy_exemplars_save.xml
test/memcpy_exemplars_save.xml successfully loaded: RISC-V 64 little general purpose compressed
[decomp]> map function 0x00000 memcpy_i2
...
[decomp]> parse line extern void memcpy_i2(void* to, void* from, long size);
[decomp]> load function memcpy_i2
Function memcpy_i2: 0x00000000
[decomp]> decompile memcpy_i2
Decompiling memcpy_i2
Decompilation complete
[decomp]> print C
void memcpy_i2(void *to,void *from,long size)
{
  vector_memcpy(to,from,2);
  return;
}
[decomp]> print raw
0
Basic Block 0 0x00000000-0x0000000c
0x00000000:7:	vector_memcpy(a0(i),a1(i),#0x2:5)
0x0000000c:6:	return(#0x0)
...
==125839== LEAK SUMMARY:
==125839==    definitely lost: 0 bytes in 0 blocks
==125839==    indirectly lost: 0 bytes in 0 blocks
==125839==      possibly lost: 0 bytes in 0 blocks

```
>Note: if logging is enabled, the output will appear at `/tmp/ghidra*.log`

So the simplest transform via plugin works in this simplest of test cases.

To exercise the plugin with the Ghidra GUI, just launch Ghidra with the plugin-enabled decompiler and an
environment variable naming the plugin:

```console
DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
```

## Next steps

There are many other ways gcc can use vector instructions to implement its `__builtin_memcpy` primitive.

The most common way is with a loop, when the number of bytes to copy is unknown to the compiler.  This
is harder to transform in Ghidra, as varnode lifetime over a loop gets complicated, indexing calculations
must be proven to be unused outside of the loop, and the Ghidra Basic Block holding the loop must be merged
with the following Basic Block.  We'll tackle that once we have a better understanding of raw PCode and Varnode
lifetimes.

The other common way involves three dimensions:
* the vector loads and stores may identify 16, 32, or 64 bit elements instead of 8 bit elements.  The rule matching
  tests need to be generalized to accept any of these, so long as they are internally consistent.  This will additionally
  imply that the Varnode representing size constant needs to be rewritten.
* the `vsetivli` instruction might set the *multiplication factor* field, requesting the operation be striped over up to
  eight contiguous vector registers.  This would allow up to 128 bytes copied without a loop.
* Other compilers may choose not to use fractional *multiplication factor* fields as a hint to the processor that portions
  of the vector registers remain unused.
