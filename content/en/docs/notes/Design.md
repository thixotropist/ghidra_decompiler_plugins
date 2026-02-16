---
title: Design
weight: 50
description: A design summary for decompiler plugins and the RISC-V vector plugin example
---

>Note: This should be considered a living document, subject to many future updates.  Many design elements
>      are likely to change rapidly, and are documented in the source code as Doxygen.

The existing code lacks clear factorization, making it hard to extend to larger transforms.  This page sketches
design principles that may help with refactoring and overall clarity.

The overall goal is to demonstrate a Ghidra decompiler plugin capability that enhances readability.  This goal is paired with
a sample plugin seeking that enhancement for RISC-V instruction set extensions, such as the Vector extension  and possibly crypto extensions.

The highest level components are:

1. Ghidra components:
    * The Ghidra GUI, cloned from the Github source repository.  No changes are made to the GUI or other Java components.
    * Ghidra SLEIGH definitions for RISC-V instruction set extensions.  We'll target the RISC-V RVA23 profile extensions
      with initial attention to the vector extension version 1.0.
    * The Ghidra decompiler source code, extracted from the most recent released Github tarball.
2. An x86_64 Linux platform with a current gcc 15 toolchain, valgrind, and gdb.
3. A Bazel build environment:
    * to import, patch, and build the `decompile` application, the `decompile_datatest` test framework, and any user plugins.
    * to crosscompile 64 bit RISC-V RVA23 application code.
4. A python integration test environment.
5. A set of RISC-V sample binaries, compiled with gcc and RVA23 profile extensions.  The `whisper-cpp` voice-to-text
   application provides most of these.
6. A set of datatest binaries, often extracted from `whisper-cpp` using Ghidra's Debug Function Decompilation capability.
7. Plugin components:
    * Patched into the released decompiler:
        1. A plugin manager to load a desired plugin when a compatible decompiler `Architecture` is instantiated.
        2. A `spdlog` logging subsystem
        3. Hooks to add new rules and datatyped builtin functions
        4. Additional methods to existing Ghidra classes in support of edits to the displayed control structure.
    * Plugin infrastructure:
        1. Diagnostic and inspection methods
        2. Dispatch points to implement new user Rules and datatyped builtin functions
    * Example plugin:
        1. Experimental code to improve readability of 64 bit RISC-V RVA23 binaries including the RVV 1.0 vector extension
8. Documentation of the plugin components and the Ghidra decompiler environment in which plugins must operate.  This
   includes the existing Doxygen descriptions of existing decompiler classes and Hugo+Docsys pages attempting to map
   the dynamics of the Ghidra decompiler.

## General design elements (draft)

* New plugin code shares the Ghidra C++ namespace
* No changes are made to the Ghidra GUI or the interface between that GUI and the decompiler
* C++-20 or newer is assumed
* Plugins are loaded as Sharable Objects - `dll` or `dylib` support is not provided
* Plugins should not leak memory
* Plugins register callback requests on specific `PcodeOps` like `CallOther`.
* Plugins register new `DataTypeUserOps` like `vector_memcpy`.  A `DataTypeUserOp` is similar
  to a User Operation where the inputs and outputs are strongly typed.
* Plugin methods that do not strictly apply to RISCV instructions should migrate to diagnostic
  or graph editing files and out of the processor-specific plugin code.

### Register lifetime heuristics

Ghidra goes to a lot of work to track variable dependencies.  A typical `vector_memcpy`
loop will use three scratch scalar registers and one scratch vector register.  This can
pose a problem when a vector loop is followed by a function call and those scratch
registers *might* be considered parameters of the called function.  The current plugin
deletes descendent links in that case.

## RISCV-RVA23 plugin specific design

>Note: this material may later be copied into Doxygen inline docs to make divergence easier to recognize and correct.

### riscv.*

These files provide context and handlers for a specific plugin.  Several
handlers are defined for direct invocation by the `PluginManager` compiled into
the base `decompile` and `decompile_datatest` binaries:

* `plugin_init` is called to initialize the plugin and pass in Ghidra's `Architecture`
  object holding processor and function data.
* `plugin_getrules` is called to add one or more new Rules to the cleanup `ActionGroup`.
  These rules are invoked after basic decompiler analysis is complete and before
  control structures are finalized and emitted as C code.
* `plugin_registerBuiltin` is called to register a single new `DatatypeUserOp`, such as
  `VECTOR_MEMCPY` or `VECTOR_MEMSET`.  These user ops have distinct input and output type
  assignments.
* `plugin_exit` is called when Ghidra's `Architecture` is destroyed.

Global variables are exported, including:

* `Architecture* arch` - a link to the Ghidra Architecture realized for this Processor and function.
* `std::map<int, RiscvUserPcode*> riscvPcodeMap` - a dictionary of RISC-V user opcodes indexed by Ghidra's internal identifier.  The RiscvUserPcode object holds names and traits
for user opcodes found in SLEIGH files.

### rule_vector_transform.*

Ghidra transforms function data via Rules.  Rules register the pcodes they consider
possible triggers, in our case the `CPUI_CALLOTHER` pcode.  The rule's `applyOp` method
is called for each trigger instance within the function being decompiled.  If the function
data is transformed within the rule, `applyOp` returns 1, otherwise 0.  Rules within an `ActionGroup` will be applied more than once until *no* rule within that group makes a change to the function.

>Warning: Ghidra will invoke the `clone` method on any Rule, effectively giving the object
>         a lifetime greater than that of the `Architecture` object loading the plugin.
>         The user plugin can not be unloaded before *all* clones of its Rules have been
>         located and destroyed.

This plugin defines a new class `RuleVectorTransform` derived from the Ghidra `Rule` class.
`RuleVectorTransform::getOpList` registers its triggers via the method `RuleVectorTransform::getOpList`
and provides the handler as the method `RuleVectorTransform::applyOp`.

`applyOp` is called on every `CALLOTHER` in the function, returning immediately if the
first argument of the `CALLOTHER` (the user Pcode identifier) is not a recognized RISC-V
`vsetvli` or `vsetivli` user pcode op.  A new `VectorMatcher` object is constructed to
extract features from the adjacent instructions and support evaluation of possible transforms.

* if the instruction is a `vsetivli`, the number of elements is known at compile time
  and no loop analysis is needed.  The local (static) function `evaluateNonLoopVectorStanza` is invoked to see if a transform into one or more `vector_memcpy` or `vector_memset` `DatatypeUserOps` is appropriate, always with a
  constant integer `size` parameter.
* if the instruction is a `vsetvli`, the number of elements is either unknown at compile
  time or too large to encode into a `vsetivli` instruction.  If the `VectorMatcher` object
  indicates a memory copy loop, then that transform is attempted. This processing is more
  complex, generally resulting in a `vector_memcpy` transform and the absorption of the
  enclosing `do..while` control block.

#### Loop free transform

`evaluateNonLoopVectorStanza` searches PcodeOps following the `vsetivli` instruction,
terminating the search after 30 PcodeOps, the end of the current Ghidra `Block`, or detection of another `vset*` instruction.

If a vector load or load immediate instruction is found, the source Varnode is examined
to see if this is a constant or a memory reference - that determines whether a
`vector_memset` or `vector_memcpy` is to be generated.  For each vector load instruction
the descendents of that instruction - instructions referencing as input the vector register
set by that vector load - are collected and transformed into `vector_memset` or `vector_memcpy` calls.  The element size and number of vector elements are used to compute
the number of bytes to set or copy.

#### VectorLoop

This class handles general feature extraction for vector stanzas including a loop.  It should
provide enough general features to allow the VectorMatcher code to identify which transform to attempt.
The general features include:

* identification of vector source and destination operands, if any
* identification of the loop control structure and the registers or Varnode tested to exit the loop
* an initial attempt to identify likely temporary registers and possible result registers.

#### VectorMatcher

This class handles specific feature extraction and basic matching for vector sequences.
The class concentrates on sequences involving loops.  The simplest case is a vector memory
copy operation with a variable number of elements to transfer:

```as
vsetvli  a3,a2,e8,m1,ta,ma
vle8.v   v1,(a1)
sub      a2,a2,a3
c.add    a0,a3
vse8.v   v1,(a0)
c.add    a1,a3
bne      a2,zero,memcpy_v1
```

The `VectorMatcher` constructor is fiven the PcodeOp corresponding to the `vsetvli` instruction, extracting these features:
* The number of elements to process is variable, defined in register `a3`
* The element size is 1 byte
* The multiplier is 1
* A simple comparison branch is found
* Varnodes are identified for:
    * the number of elements to process (`a2` in the code above)
    * the number of elements per loop (`a3` in the code above)
    * the source pointer (`a1`)
    * the destination pointer (`a0`)
* The control structure is a simple loop, with no other branch or call instructions
* Vector load and store instructions reference the same vector register (`v1`)
* No other vector instructions were found within the loop.
* Three arithmetic operations were found within the loop, correct for source and destination
  pointer adjustments and a counter decrement.

With that the matcher has enough to assert a match to a vector memory copy builtin.
The relevant code asserting the match is:

```c
bool VectorMatcher::isMemcpy()
{
    bool match = simpleFlowStructure && simpleLoadStoreStructure && foundSimpleComparison &&
        vectorRegistersMatch && (numArithmeticOps >=3) && (!foundUnexpectedOp) &&
        (!foundOtherUserPcodes);
    return match;
}
```

Finding a match doesn't mean a transform is safe, just that a `vector_memcpy`
transform should be attempted and other transforms not attempted.

A completed transform will look like:

```c
vector_memcpy(a0, a1, a2);
```

We would like the matcher to handle other patterns, including:
* `vector_memset(dest, value, variable_size)`
* `strlen(string)`
* `std::transform(src.begin(), src.end(), dest.begin(), lambda_expression)`
* `std::reduce(src.begin(), src.end(), initial_value, lambda_expression)`

The `vector_memset` pattern is similar to `vector_memcpy` without a vector load inside the loop
and without a source pointer register or register increment instruction.

The `strlen` pattern is a bit more complex, involving setup instructions before the vector loop and final reduction
instructions after the loop.

The `std::transform` pattern is more complex but very common - you see this a lot in loops over sequences of structure pointers.

The `std::reduce` pattern is also common, found in control system loops and as a general case of the very common vector inner product
calculation.

A compiled vector sequence that is well outside our ability to match is comes from code like this:

```c
// copy an array of uint64's in reverse order
void reverse(unsigned long long *in, unsigned long long *out, unsigned int size)
{
    int i;
    int upper_index = size - 1;
    for (i=0; i < size; i++) {
        out[i] = in[upper_index - i];
    }
}
```

When compiled with `-march=rv64gcv -O3` options Ghidra gives us
```c
  if (size != 0) {
    uVar5 = (ulong)((int)size + -1);
    if (0xc < uVar5) {
      if (((ulong)(long)((int)(in_vlenb >> 3) + -1) <= uVar5) &&
         ((out + (size & 0xffffffff) <= in + ((uVar5 + 1) - (size & 0xffffffff)) ||
          (in + uVar5 + 1 <= out)))) {
        vsetvli_e64m1tama(0);
        auVar10 = vid_v();
        auVar10 = vrsub_vx(auVar10,(in_vlenb >> 3) - 1);
        lVar6 = ((uVar5 * 8 + 8) - in_vlenb) + (long)in;
        iVar1 = (int)(in_vlenb >> 3);
        uVar8 = 0;
        puVar3 = out;
        do {
          auVar9 = vl1re64_v(lVar6);
          uVar8 = (ulong)((int)uVar8 + iVar1);
          lVar6 = lVar6 - in_vlenb;
          auVar9 = vrgather_vv(auVar9,auVar10);
          vs1r_v(auVar9,puVar3);
          puVar3 = (ulonglong *)((long)puVar3 + in_vlenb);
        } while (uVar8 <= (ulong)(long)((int)size - iVar1));
        if (size == uVar8) {
          return;
        }
        puVar7 = in + (uVar5 - uVar8);
        puVar3 = out + uVar8;
        do {
          uVar4 = *puVar7;
          uVar8 = (ulong)((int)uVar8 + 1);
          puVar7 = puVar7 + -1;
          *puVar3 = uVar4;
          puVar3 = puVar3 + 1;
        } while (uVar8 < size);
        return;
      }
    }
    puVar7 = in + uVar5;
    puVar3 = out;
    do {
      uVar4 = *puVar7;
      puVar2 = puVar3 + 1;
      puVar7 = puVar7 + -1;
      *puVar3 = uVar4;
      puVar3 = puVar2;
    } while (puVar2 != out + (size & 0xffffffff));
  }
  return;
  ```

That's 14 Ghidra blocks to implement a simple loop.  We won't attempt to match that pattern, but will keep in mind this kind of vectorization.

* If more than 0xc elements are to be reverse-copied, a vector implementation is used.  Otherwise a simple scalar loop is used.
* The vector implementation uses some unusual vector instructions to manage the source pointer arithmetic.
* The vector implementation reverts to a scalar implementation to handle any remaining elements that don't fill up a vector register.