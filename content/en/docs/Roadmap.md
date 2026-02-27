---
title: Roadmap
description: There are many paths forward radiating outward from this project - which ones are worth researching?
weight: 80
---

We want to capture intermediate and longer term goals, and to start measuring the speed at which those goals might be
reached.  Short term goals will likely remain captured as Issues, Feature Branches, and WIP pull requests.  This Roadmap
will include at least two dimensions:

* General decompiler framework elements, such as plugin code and instrumentation and explorations of decompiler internals.
  Examples include:
    * Document decompiler [action groups]({{< relref "Action_database.md" >}}) and their sequencing, showing the stages
      during which PCode is ingested, Blocks identified, type information propagated and casts assigned, higher level control
      flow blocks assigned, referential integrity checks performed, and C-like code emitted.
    * Consider using the GCC internal compiler unit tests to 'train' feature analytics within the decompiler.  These
      analytics might perform BSIM-like comparisons of unknown instruction sequences to display the C test case sources most
      likely to generate similar instruction sequences.
      The sister project [Ghidra Advisor](https://github.com/thixotropist/ghidra_advisor) makes some early steps in this
      direction.
* Initiatives specific to enhanced evaluation of RISC-V AI-enhanced embedded systems.  Examples include:
    * Extend decompiler dependency analysis to propagate vector status register load immediate context data into the Blocks
      they control, so that PCode can be specialized from the most basic unsegmented, tail and mask agnostic configuration
      baseline now assumed.
    * Collect and identify the different types of RISC-V vector instruction sequences, separating vectorization of C,
      compilation of explicit RISC-V [vector intrinsics](https://github.com/riscv-non-isa/rvv-intrinsic-doc/tree/main/doc),
      compiler inline assembly, explicit assembly, and kernel inline assembly injection.

Ideally, the Roadmap would identify other goals worth pursuing, and provide estimates of the amount of effort needed to
approach those goals.  Examples:
* RISC-V inference engine apps will likely use two different 16 bit floating point representations as vector element types.
  What is the scale of changes needed to create and represent novel intrinsic types within the decompiler?

This Roadmap is complicated by the multiple, overlapping goals implicit in this project.  Let's summarize them and hope we can find a way to factor them into coherent thrusts.

* Show the cost/benefit tradeoffs for adding new features to the Ghidra Decompiler *without* waiting for decompiler Pull
  Requests to be reviewed and approved.
    * [X] Add a basic decompiler plugin capability adding new Rules to the `cleanup` `ActionGroup`.
    * [X] Add a basic decompiler logging capability
    * [X] Add decompiler `Inspector` classes to help explore runtime data structures
    * [X] Add decompiler graph editor classes to rewrite nodes in the `BlockGraph`, altering or absorbing higher level C
      structures like `do ... while` blocks.
    * [ ] Document the complexity of each of these added capabilities, giving lines of code and estimated stability.
* Demonstrate a RISC-V processor-specific decompiler plugin capable of recognizing common vector instruction sequences
  and condensing them into user-friendly typed function calls.
    * [X] Start with vectorized common C library routines like `memcpy` and `strlen`
    * [ ] Explore more complicated and mutable transform and reduction patterns.
* Demonstrate possible workflows for applying Ghidra to networked AI-enhanced embedded systems.
    * This is likely an iterative process starting with the executable to be analyzed and adapting the computer toolchain
      and Ghidra decompiler to better align with that executable.
* Explore options for deferring instruction semantic decoding from initial binary import (via SLEIGH file definitions) until
  after basic control flow analysis provides a better view of the context in which instructions execute.
    * Instruction semantics today are not fully known and decodable until runtime, where R/W fields in certain Control and
      Status registers effectively extend instruction opcodes.

## Non-goals

* Don't try to support Ghidra emulation or debugging of ISA vector extensions.
  Qemu RISC-V vector emulation code exceeds 20K lines of code that don't need to be replicated within Ghidra.
* Don't try to solve the general problem of decompiling vectorized code.  Instead, concentrate on the most common loop
  vectorizations of a single Gnu compiler building for a single (but generic) microarchitecture).
