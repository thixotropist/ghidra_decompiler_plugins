# Plugins

Plugins are experimental.  We hope to evaluate the feasibility of both user-contributed and processor-specific plugins.
The initial goal is to extend @caheckman commits transforming pcode sequences into `builtin_memcpy` calls, translating
common RISCV-64 vector instruction sequences into `builtin_memcpy`, `builtin_strlen`, and other higher level calls.

The project documentation consists of a Hugo static website under `content/en`.

# Quickstart

Adding new Actions to the Ghidra decompiler can take some trial and error, so we want to avoid having to rebuild
all of Ghidra on each test iteration.  The decompiler stands as a separate C++ executable Feature within Ghidra.
That executable can easily be patched to enable run-time plugins.  Therefore a fairly simple development workflow
can be:

1. Install a Ghidra distribution binary tarball.  For example, we install Ghidra /opt/ghidra_11.4_DEV from the
   `isa_ext` branch of https://github.com/thixotropist/ghidra.  This branch includes support for RISCV vector
   instruction set extensions.  The distribution's Ghidra decompiler gets installed at
   `/opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompiler`.
2. Acquire a Ghidra distribution source tarball to get the decompiler sources, patch a simple plugin manager into
   those sources, and rebuild the decompiler.  The rebuilt decompiler will export all linkage symbols for access by
   a plugin.
3. Build a local plugin as a Sharable Object library accessing the decompiler's API.  In this example, the
   plugin is `libriscv_vector.so`.
4. Copy the plugin to some accessible location, say `/tmp`.
5. Launch `ghidraRun` with the plugin file passed in via an environment variable.

```console
# Build the Ghidra decompiler from the distribution sources.
# The distribution is patched locally to include a simple decompiler plugin manager
$ bazel build -c opt @ghidra//:decompile

# replace the unpatched decompiler with our modified decompiler
$ cp -f bazel-bin/external/+_repo_rules+ghidra/decompile /opt/ghidra_11.4_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/

# build a decompiler plugin that can recognize vectorization of memcpy and memset invocations
$ bazel build -c dbg plugins:riscv_vector

# copy the plugin somewhere accessible
$ cp -f bazel-bin/plugins/libriscv_vector.so /tmp

# launch Ghidra with a path to the plugin passed via DECOMP_PLUGIN
$ DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
```

Plugin development uses the decompiler's datatest infrastructure, so compile/link/test cycles can be a matter of seconds.
There is no need to rebuild either Ghidra or the decompiler module for every small change to the plugin logic.

## Notes

This approach to decompiler extensions avoids any Pull Request approvals to decompiler sources. The decompiler patches
needed to support plugins are self-contained within the workspace.
