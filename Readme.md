# Overview

>Note: This project is one of [several](https://github.com/thixotropist) projects exploring Ghidra tools to make
>      analysis of RISC-V AI-enhanced applications easier.

The bulk of this project's documentation is structured as a Hugo + Docsys static web site,
with source material collected under `content/en`. Local browsing is enabled with `hugo serve`.  Plugin code choices are
mostly documented as inline Doxygen comments, as they are likely to evolve along with the code they describe.

The intended audience includes Ghidra users wishing to extend or research Ghidra's decompiler subsystem,
especially in support of processor-specific Rules and Actions.
This sample project concentrates on rules enhancing readability when analyzing programs using instruction
set architecture extensions like the RISC-V vector instruction set.  Anything that reduces the time for a user to answer the question
"Do I care what's going on here?" when looking at a function in Ghidra's decompiler window is in scope.  That also means that residual
errors are acceptable, so long as net insights-per-hour improves.

This is a research project intended to show what *may* be done with the Ghidra decompiler and at what complexity.
We can avoid the complexity of full Ghidra decompiler Pull Request reviews by proposing no enduring changes to the decompiler
itself.  Instead, the first decompiler plugin build triggers a download of current released (in the *release* branch) Ghidra sources,
or development tip (in the *main* and feature-development branches).  These are then
patched to provide the decompiler with a minimal plugin manager.
Exploratory development then proceeds within the plugin, using the decompiler's native datatest framework for
rapid build/test iterations.

A secondary goal is to supplement @caheckman's excellent Doxygen documentation of the decompiler source code, for instance
documenting examples of `PcodeOp` and `Varnode` transformations, descendent tracking, and object lifetimes.

Code samples in this project are likely to be continuously refactored, starting from a very rough but simple initial
design.

Much of the material here has been adapted from the excellent prior work by

* [Chris Heckman](https://github.com/caheckman)
* [Luke Serné](https://github.com/LukeSerne)
* [mumbel](https://github.com/mumbel)
* [Joakim Nohlgård](https://github.com/jnohlgard)

## Why RISC-V?

This project explores evolutionary drivers likely to affect Ghidra.  Are new types of binaries likely to appear in three years?
Will it take five years for Ghidra to evolve to meet that need?  In an ideal world we would have a five year projection of Ghidra
requirements coupled with a five year Ghidra Roadmap of new features satisfying those requirements.

The RISC-V processor makes a good 'lab animal' for this kind of research, as it is able to evolve rapidly, and without
licensing restrictions.  It's a useful equivalent of a biologist's fruit fly or human stem cell collection.  That also makes RISC-V
a useful evolutionary marker for innovations in multiprocessor, kernel, user libraries, and embedded system designs.

We need a concrete goal or challenge to narrow the application space for Ghidra plugin research.
This project chooses something provocative: Extend Ghidra to better analyze firmware likely to be found in AI-enhanced weaponized drone swarms,
where that firmware is built on semi-custom RISC-V hardware and open-source software.

## A Decompiler Plugin Development Workspace

Plugins are experimental.  We hope to evaluate the feasibility of both user-contributed and processor-specific plugins.
The initial goal is to extend @caheckman commits transforming pcode sequences into `builtin_memcpy` calls, translating
common RISCV-64 vector instruction sequences into `vector_memcpy`, `vector_strlen`, and other higher level calls.

## Quickstart

Adding new Actions to the Ghidra decompiler can take some trial and error, so we want to avoid having to rebuild
all of Ghidra on each test iteration.  The decompiler stands as a separate C++ executable Feature within Ghidra.
That executable can easily be patched to enable run-time plugins.  Therefore a fairly simple development workflow
can be:

1. Install a Ghidra distribution binary tarball.  For example, we install Ghidra /opt/ghidra_12.1_DEV from the
   `isa_ext` branch of https://github.com/thixotropist/ghidra.  This branch includes support for RISCV vector
   instruction set extensions.  The distribution's Ghidra decompiler gets installed at
   `/opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompiler`.
2. Acquire Ghidra distribution sources via http or git to get the decompiler sources, patch a simple plugin manager into
   those sources, and rebuild the decompiler.  The rebuilt decompiler will export all linkage symbols for access by
   a plugin.
    * The Ghidra decompiler patch set will likely include other methods needed to edit control structures, as
      many vector transforms involve absorbing simple loops or merging blocks.
3. Build a local plugin as a Sharable Object library accessing the decompiler's API.  In this example, the
   plugin is `libriscv_vector.so`.
4. Copy the plugin to some accessible location, for example `/tmp`.
5. Launch `ghidraRun` with the plugin file passed in via an environment variable: `DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun`

```console
# Build the Ghidra decompiler from the distribution sources.
# The distribution is patched locally to include a simple decompiler plugin manager
$ bazel build -c opt @ghidra//:decompile

# replace the unpatched decompiler with our modified decompiler
$ cp -f bazel-bin/external/+_repo_rules+ghidra/decompile /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/

# build a decompiler plugin that can recognize vectorization of memcpy and memset invocations
$ bazel build -c dbg plugins:riscv_vector

# copy the plugin somewhere accessible
$ cp -f bazel-bin/plugins/libriscv_vector.so /tmp

# launch Ghidra with a path to the plugin passed via DECOMP_PLUGIN
$ DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
```

Plugin development uses the decompiler's datatest infrastructure, so compile/link/test cycles can be a matter of seconds
with no involvement of the Ghidra GUI.
There is no need to rebuild either Ghidra or the decompiler module for every small change to the plugin logic.

This approach to decompiler extensions avoids any Pull Request approvals to decompiler sources. The decompiler patches
needed to support plugins are self-contained within the workspace.

## Current Status

What works:

* A simple Ghidra decompiler plugin framework is working on a Linux host.  The plugin activates with both the
  usual Ghidra GUI environment and the standalone Ghidra decompiler datatest framework.
* The plugin manager adds hooks to add custom actions and new Datatyped builtin functions like `vector_memcpy` and `vector_memset`.
* The elementary proof-of-concept plugin recognizes *some* RISCV vector sequences and transforms them into `vector_memcpy` and
  `vector_memset` calls.
* Applying the new plugin rule to a vectorized RISC-V build of `whisper-cpp` completes without crashing and generates over 1500
  vector transforms.
* Varnodes assigned by the decompiler and used exclusively within a vector stanza are deleted, reducing clutter.
* Vector stanza loops are absorbed into `vector_*` function calls, updating the parent function's `BlockGraph` to show the
  simplified control flow.

What's pending:

* Add more builtins, like `vector_strlen`.  Recognizing these sequences is mostly working, generating safe transforms is in the TODO list.
* General editing for consistency and ease of access.  For example, using namespaces to separate decompiler core and RISC-V plugin
  methods and types.
* We need a general model for vector instruction stanzas implementing loops over arrays of structures.  This *may* lead
  to `vector_map` transforms similar to `std::transform` where the scalar operation is a lambda expression.

Current plugin framework lessons-learned  snapshot:

* Decompiler plugins are easy to support in Linux.  This project does not attempt to extend that to other platforms.
* Ghidra's decompiler internal API is very well documented.  Other aspects, such as object lifetime and the hierarchy of Actions,
  ActionGroups, and Rule invocations could use more documentation.  A design document discussing referential integrity checks and
  when they are applied would be very useful.
* Decompiler PCode changes rapidly within a decompiler session.  If a user plugin completes a transform, the decompiler will
  likely rewrite those new PCodeOps and Varnodes within milliseconds to fixup typecasts and delete what looks like dead code.

Current RISC-V transforms lessons-learned snapshot:

* A RISC-V plugin can significantly improve decompiler output readability, especially if tuned to patterns often emitted by current
  compilers.  Assembly sequences emitted by GCC builtins like `builtin_memcpy` make a good example of patterns worth transforming.
  Assembly sequences generated with the GCC loop vectorization test suite would be an excellent training set of new - and much tougher - patterns.  Obfuscated code would fair poorly, since it is so easy to generate patterns that make no sense until runtime.
* The RISC-V vector extensions do not in general allow simple PCode SLEIGH semantic sections. RISC-V vector instruction decoding
  on-chip is intrinsically a run-time action, based not on just the 32 bit instruction but a concatenation of vector and other CSR
  register fields with that instruction.  It is likely - but not proven - that the Ghidra decompiler can partially fixup the base
  SLEIGH PCode decoding after full control flow analysis is complete and the context of relevant vector CSRs is better known.
* Vector instructions are commonly found in Inference Engine applications, implementing things like floating point dot products and
  reduction sums.  Surprisingly, vector instructions are also found in general device drivers and embedded system code.
  Simple `memcpy` and `strlen`stanzas are to be expected there and are easy to recognize and transform.
  Device drivers often include loops over arrays of control structures, polling for status or collecting sensor data.
  Vectorized `transform`, `reduce`, or `apply` loops will need a lot of attention to be recognizable by Ghidra users.  A simple vectorized loop reversing elements in an array can easily take a user hours to comprehend.
* Pay less attention to vector sequences that a compiler is unlikely to generate.  Vector instructions that use Multiplier or
  Grouping semantics to apply to 2, 4, or 8 registers in parallel are less likely to be generated and found in systems for several
  years. Current micro-architectures don't appear to yet show better performance on these vector sequences.
* Hand-generated vector code, perhaps using RISC-V vector C functions, are likely less common than compiler-generated code.  Humans just
  do a relatively poor job of adapting C for diverse micro-architectures than compiler code contributed by GCC micro-architecture
  specialists.
* Inference Engine applications are likely to make heavy use of 16 bit floating point operations and vector bit manipulation
  instructions when processing sub-byte quantization fields.  Teaching Ghidra to cope with new fundamental types like this will
  be painful.  Hopefully that layer is too deep to attract vulnerabilities.
