---
title: Workspace Layout
weight: 10
---

This workspace supports experiments with Ghidra's decompiler, a C++ executable usually invoked from the Ghidra Java User Interface.
The primary components are:

* A `PluginManager` patched into the source for a released Ghidra distribution.
    * The patches are found in the file `ghidra.pat` and applied to the Ghidra source tarball
      named in `MODULE.bazel`.  This patch file can be regenerated with a command like `git diff main..plugin_patches > ../ghidra.pat`
      in a git repo with two branches, one matching the released tar file and one implementing the plugin manager and its access points.
    * The patched `decompile` executable is built with a command like `bazel build -c opt @ghidra//:decompile`,
      with the executable found in `bazel-bin/external/+_repo_rules+ghidra/decompile`
      The Ghidra source tarball will be fetched and patched if not already in the cache.
* A plugin loaded into the decompiler at Ghidra initialization
    * Plugin source code is found in the `plugins` directory.
    * The plugin can be built with `bazel build -c opt  plugins:riscv_vector` and installed anywhere,
      typically `/tmp/libriscv_vector.so`.
    * Source code changes to a plugin do not generally require rebuilding the `decompile` invoked by Ghidra.
* Additional Ghidra decompiler datatests to verify plugin transforms outside of a full Ghidra integration.
* Extracting the Ghidra decompiler Doxygen html tree into your workspace is highly recommended.
* Supporting documentation on how to use plugins to add new, user-supplied decompiler Actions and transformations.
    * The driving example here is recognition of RISC-V vector instruction sequences and translating them into something
      friendlier to the user, such as `builtin_memcpy`, `builtin_strlen`, or other method calls.

Using a new plugin is simple:
* replace `Ghidra/Features/Decompiler/os/linux_x86_64/decompile` with the plugin-enabled executable built by `bazel build -c opt @ghidra//:decompile`.
* invoke ghidraRun with the plugin's location as an environment value:

```console
$ DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
```