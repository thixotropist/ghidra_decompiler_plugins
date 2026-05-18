---
title: Workspace Components
description: This workspace includes a plugin manager and a sample CPU-specific plugin
weight: 10
---

This workspace supports experiments with Ghidra's decompiler, a C++ executable usually invoked from the Ghidra Java User Interface.
Primary components include the plugin manager, a demo plugin supporting RISC-V vector instructions, and test/documentation frameworks.

* A `PluginManager` patched into the source for a released Ghidra distribution.
    * The patches are found in the file `ghidra.pat` and applied to the Ghidra source tarball
      named in `MODULE.bazel`.  This patch file can be regenerated with a command like `git diff main..plugin_patches > ../ghidra.pat`
      in a git repo with two branches, one matching the released tar file and one implementing the plugin manager and its access points.
    * The patched `decompile` executable is built with a command like `bazel build -c opt @ghidra//:decompile`,
      with the executable found in `bazel-bin/external/+_repo_rules+ghidra/decompile`
      The Ghidra source tarball will be fetched and patched if not already in the cache.
    * All C++ compilations use the local compiler's default c++ standard.
* A plugin loaded into the decompiler at Ghidra decompiler initialization
    * Plugin source code is found in the `plugins` directory.
    * The plugin can be built with `bazel build -c opt plugins:riscv_vector` and installed anywhere,
      in our example to `/tmp/libriscv_vector.so`.
    * Source code changes to a plugin do not generally require rebuilding the `decompile` invoked by Ghidra.
* Additional Ghidra decompiler datatests to verify plugin transforms outside of a full Ghidra integration.
* Extracting the Ghidra decompiler Doxygen html tree into your workspace is highly recommended.
* Supporting documentation on how to use plugins to add new, user-supplied decompiler Actions and transformations.
    * The driving example here is recognition of RISC-V vector instruction sequences and translating them into something
      friendlier to the user, such as `vector_memcpy`, `vector_memset`, `vector_strlen`, or other method calls.

Using a new plugin is simple:
* replace `Ghidra/Features/Decompiler/os/linux_x86_64/decompile` with the plugin-enabled executable built by `bazel build -c opt @ghidra//:decompile`.
* invoke `ghidraRun` with the plugin's location as an environment value:

```console
$ DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
```

## Patching a specific Ghidra branch

Building a Ghidra plugin starts with selecting a remote Ghidra branch and commit as the baseline.
This remote is named in the `MODULE.bazel` file:

```python
git_repository(
    name = "ghidra",
    remote = "git@github.com:thixotropist/ghidra.git",
    # This commit should be within the "isa_ext" branch
    commit = "2bcf7c1ba547c2c3460f76b5c1e837409a1f97dc",
    build_file = "//:BUILD.ghidra",
    patches = ["ghidra.pat"],
    patch_strip = 1,
)
```

For this example, we want a fork of Ghidra 12.0.3 with added RISC-V SLEIGH definitions.
This remote is used in several ways:

1. Build and deploy the baseline Ghidra.  We want to use the Java GUI unchanged from the Ghidra release
   with the added RISC-V vector SLEIGH definitions provided in the `isa_ext` branch.  Our deployment directory
   will be `/opt/ghidra_12.1_DEV/`
2. We need to develop a patch containing the decompiler plugin manager.  That can be done in a new branch of
   the `isa_ext` branch commit named `patched`.  From this we can derive the patch file `ghidra.pat`.
3. The Bazel Module manager then fetches a new copy of the Ghidra source repo, applying the patch file `ghidra.pat`.
   It builds just `decompile` and `decompile_datatest`, which now have support for dynamic loading of decompiler
   plugins plus some additional logging and inspection infrastructure.

The user can now replace the baseline versions of `decompile` and `decompile_datatest` with the patched versions,
then proceed to building and exercising individual plugins.

{{< figure src=/docs/images/workspace.svg align="center" >}}