# Overview

The bulk of this project's documentation is structured as a Hugo + Docsys static web site,
with source material collected under `content/en`. Local browsing is enabled with `hugo serve`.

The intended audience includes Ghidra users wishing to extend or research Ghidra's decompiler subsystem,
especially in support of processor-specific Rules and Actions.
This sample project concentrates on rules supporting instruction set architecture extensions like the
RISC-V vector instruction set.

This is a research project intended to show what *may* be done with the Ghidra decompiler and at what complexity.
We can avoid the complexity of full Ghidra decompiler Pull Request reviews by proposing no enduring changes to the decompiler
itself.  Instead, the first decompiler plugin build triggers a download of current released Ghidra sources,
which are patched to provide the decompiler with a minimal plugin manager.
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

## A Decompiler Plugin Development Workspace

Plugins are experimental.  We hope to evaluate the feasibility of both user-contributed and processor-specific plugins.
The initial goal is to extend @caheckman commits transforming pcode sequences into `builtin_memcpy` calls, translating
common RISCV-64 vector instruction sequences into `vector_memcpy`, `vector_strlen`, and other higher level calls.

## Quickstart

Adding new Actions to the Ghidra decompiler can take some trial and error, so we want to avoid having to rebuild
all of Ghidra on each test iteration.  The decompiler stands as a separate C++ executable Feature within Ghidra.
That executable can easily be patched to enable run-time plugins.  Therefore a fairly simple development workflow
can be:

1. Install a Ghidra distribution binary tarball.  For example, we install Ghidra /opt/ghidra_11.5_DEV from the
   `isa_ext` branch of https://github.com/thixotropist/ghidra.  This branch includes support for RISCV vector
   instruction set extensions.  The distribution's Ghidra decompiler gets installed at
   `/opt/ghidra_11.5_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompiler`.
2. Acquire a Ghidra distribution source tarball to get the decompiler sources, patch a simple plugin manager into
   those sources, and rebuild the decompiler.  The rebuilt decompiler will export all linkage symbols for access by
   a plugin.
3. Build a local plugin as a Sharable Object library accessing the decompiler's API.  In this example, the
   plugin is `libriscv_vector.so`.
4. Copy the plugin to some accessible location, for example `/tmp`.
5. Launch `ghidraRun` with the plugin file passed in via an environment variable: `DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun`

```console
# Build the Ghidra decompiler from the distribution sources.
# The distribution is patched locally to include a simple decompiler plugin manager
$ bazel build -c opt @ghidra//:decompile

# replace the unpatched decompiler with our modified decompiler
$ cp -f bazel-bin/external/+_repo_rules+ghidra/decompile /opt/ghidra_11.5_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/

# build a decompiler plugin that can recognize vectorization of memcpy and memset invocations
$ bazel build -c dbg plugins:riscv_vector

# copy the plugin somewhere accessible
$ cp -f bazel-bin/plugins/libriscv_vector.so /tmp

# launch Ghidra with a path to the plugin passed via DECOMP_PLUGIN
$ DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
```

Plugin development uses the decompiler's datatest infrastructure, so compile/link/test cycles can be a matter of seconds.
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
* Applying the new plugin rule to a vectorized RISC-V build of `whisper-cpp` completes without crashing and generates over 1000
  vector transforms.

What's pending:

* Vector stanzas often consist of short loops with scalar registers assigned for source pointer, destination pointer, and counts.
  Ghidra generally considers these scratch registers as having larger scope.  If the loop is absorbed into a function call
  like `vector_memcpy` these register varnodes need to be deleted along with their descendants.  Figuring out when this is
  safe is more art than science.
* Vector stanza loops are replaced with function calls but the `BlockGraph` is not updated for the parent function.  This
  leaves `DoWhile` `FlowBlock` objects in the function's `BlockGraph`, adding clutter to the decompiler output.  We need some
  way to delete these `DoWhile` blocks and merge their interior BlockBasic code into the following blocks.
* We need a general model for vector instruction stanzas implementing loops over arrays of structures.
