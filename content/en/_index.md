---
title: Understanding RISC-V vector instruction sequences in Ghidra
---

{{% blocks/section color='white' %}}

## Introduction

Ghidra's decompiler uses a system of rules, actions, and transforms to process a function's SLEIGH pcode operators
into something looking like C source code.  This project explores the cost/complexity tradeoffs of extending
those rules, for example in a processor-specific or language-specific way.  Ghidra's released decompiler already
includes Actions (pcode transformations) that turn a series of simple loads and stores into a call to `builtin_memcpy`.
As a driving example this project expands that capability to Actions transforming vector loads and stores into a similar call to `vector_memcpy`
or `vector_memset`.
This would be useful in data initialization and copy constructors.  Other Actions may recognize and transform vector
inline coding for `strlen` into calls to `vector_strlen`, recognize other transformation and reduction loops, etc.

Ghidra's decompiler has few maintainers, so we want to add these extensions with a minimum impact on those maintainers.
That means any transforms created here should be tested and applied locally, not implemented directly
in the distributed Ghidra source archives.  This project captures those transforms as C++ plugins to be loaded
into a Ghidra decompiler patched to support general purpose plugins.

Our initial scope is in support of Ghidra analysis of RISC-V 64 bit binaries, compiled with a current gcc-15 compiler for processors matching
the general purpose [RVA23U64](https://github.com/riscv/riscv-profiles/blob/main/src/rva23-profile.adoc#rva23u64-mandatory-extensions) profile.
This includes vector (aka SIMD) instructions as well as instruction extensions useful in AI or inference engine applications.
Ghidra's SLEIGH subsystem should include user pcodeops for those instructions, such as those provided by Ghidra [PR #5778](https://github.com/NationalSecurityAgency/ghidra/pull/5778).

## Example

Current instances of gcc can convert calls to the standard function `memcpy` to its own
`__builtin_memcpy` RTL method, then generate inline vector instructions to implement that
copy operation.  The instruction sequence generated will vary, based on what the compiler
can determine about alignment and number of bytes to copy.  

For example, `gcc` with `-march=rv64gcv` can compile `__builtin_memcpy(to, from, 8)` into a vector instruction sequence like

```as
    vsetivli  zero,0x8,e8,mf2,ta,ma  # 0x8 = number of 8 bit elements 
    vle8.v    v1,(a1)                # a1 = from address
    vse8.v    v1,(a0)                # a0 = to address
```

If gcc has compile-time information that `to` and `from` are both arrays of four 16 bit elements,
the generated code might look like this instead:

```as
    vsetivli   zero,0x4,e16,mf2,ta,ma # 0x4 = number of 16 bit elements 
    vle16.v    v1,(a1)                # a1 = from
    vse16.v    v1,(a0)                # a0 = to
```

The basic rule appears to be that if a scalar sequence would trigger an alignment exception
then the vector sequences should do so as well.

Ghidra's decompiler currently supports the transformation of sequences of scalar loads and
stores into a single `builtin_memcpy` line in the decompiler window.
What is the complexity of teaching Ghidra to do the same with vector loads and stores?

More generally, can we add processor-specific decompiler plugins to Ghidra and let users experiment with
this kind of transform?

## Installation

>Note: This project is tested against Ghidra 11.4 and 11.5.  Documentation may refer to either release
       with no known release dependencies.

This project patches an existing Ghidra deployment, replacing the standard decompiler executable
with one supporting a simple plugin manager.  It also provides a framework for developing and
testing decompiler plugins capable of adding new rules, actions, and transformations.

1. Install Ghidra from any source.  For this project, we install the `isa_ext` branch from `git@github.com:thixotropist/ghidra.git` to `/opt/ghidra_11.5_DEV`.
   This will provide every Ghidra component *except* for the decompiler.
2. Allow changes to the decompiler directory.
   ```console
   $ chown -R username:groupname /opt/ghidra_11.5_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/
   ```
3. Install [Bazel](https://bazel.build/) as a workspace/build manager on your system.
4. Download this project from the github repository.
5. Select the Ghidra tarball providing decompiler source, then edit the path into `MODULE.bazel`.
   We will use `Ghidra_11.4_build.tar.gz` from Github.
6. Build the patched decompiler and its associated datatest and unittest executables
    ```console
    $ bazel build -c dbg @ghidra//:decompile @ghidra//:decompile_datatest @ghidra//:decompile_unittest
    ```
7. Replace the original decompiler with the patched decompiler
    ```console
    $ cp -f bazel-out/k8-dbg/bin/external/+_repo_rules+ghidra/{decompile,decompile_datatest,decompile_unittest} \
    /opt/ghidra_11.5_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/
    ```

Notes:

* This project interworks two Ghidra versions, so there is a possibility of version skew.  The Ghidra GUI and processor/SLEIGH
  code is currently built from a fork of the Ghidra development code, e.g. `ghidra_11.5_DEV`.  The decompiler is built from
  a patched full release, e.g. `ghidra_11.4`.  The API between the two changes slowly, and is unlikely to raise serious issues
  during experiments.
* Bazel will fetch and locally cache the Ghidra source archive on the first build.
    * If you later want to alter the decompiler patch file `ghidra.pat`, you should execute `bazel clean --expunge` to update the cached and patched
      archive.
* You can compile the patched decompiler with optimization by replacing `dbg` with `opt` in the
  last 2 steps.
* The Bazel build file `BUILD.ghidra` controls the Ghidra decompiler elements made available to
  any plugin.  The default is to make all decompiler symbols available to the plugin.
* Isolating new rules to a decompiler plugin makes the code/test cycle time very fast.  We want good logging capabilities for the plugin,
  so we include a `spdlog` module in the decompiler build for use by the plugin manager and individual plugins.

## Plugin development and usage

Decompiler plugins can now be built and used.  Builds should be very fast, as neither the Ghidra
GUI nor the decompiler need to be rebuilt.  The plugin is built as a sharable object file, here `/tmp/libriscv_vector.so`.

```console
$ bazel build -c dbg plugins:riscv_vector
...
$ cp bazel-bin/plugins/libriscv_vector.so /tmp
```

To use this plugin, simply name it when invoking `ghidraRun`:

```console
DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
```

Notes:

* Plugins need to use the full Ghidra path when including header files.  If the plugin needs `ruleaction.hh` from the decompiler source, it will use an include statement like
    ```c
    #include "Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh"
    ```

{{% /blocks/section %}}
