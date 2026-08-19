---
title: Updating to new Ghidra releases
description: A new Ghidra release - or major change to the development tip - means multiple updates to the plugin framework and individual plugins.  That process has many steps.
weight: 100
---

A working decompiler plugin relies on synchronization between many moving parts:

1. The Ghidra GUI, which offers the overall user experience.
2. The decompiler providing C-like representations of individual functions.
3. SLEIGH processor definitions.
4. The patch file needed to add PluginManager capabilities to the decompiler.
5. Individual decompiler plugins loaded by a patched decompiler.

Additionally we need synchronization in two APIs
1. The socket-level API between the GUI and the decompilers.
2. The C++ API offered by the decompiler to its components, the PluginManager, and the sample plugin demonstrated here.

This page captures the update process when that C++ API is updated in a way that impacts the
RISC-V vector plugin.

We will use as an example an update from August 2026.
The key Ghidra decompiler change here involves a core Ghidra developer
splitting/subclassing the `BlockIf` class to add `BlockIfNext`, `BlockIfGoto`, `BlockIfNoExit`
classes.  The existing plugin framework knows how to:
* traverse and log a `BlockGraph` containing `BlockIf` objects, but not the three new classes.
* traverse and replace edge references in a `BlockGraph` containing `BlockIf` objects,
  but not in the three new classes.  This traversal is necessary when programmatically editing
  the function's `BlockGraph`, for instance to replace a vector loop block with a `vector_*`
  builtin function call.

## Establish a working baseline

>Note: *working baseline* means the top level `integration_test.py` completes successfully
>      except for any known failing test cases collected under `DEFERRED_TESTS`.

The example Ghidra decompiler plugin depends on a pending [PR](https://github.com/NationalSecurityAgency/ghidra/pull/5778), so updates occur in two phases:

* Rebase the [PR fork](https://github.com/thixotropist/ghidra/tree/isa_ext) to either the tip
  of the Ghidra master development branch or a point release, building/testing/deploying it locally to something like `/opt/ghidra_12.2_DEV`.
* Locate and resolve any anomalies in the plugin manager framework or the sample RISC-V plugin,
  by iterating with `integration_test.py`.

### Identifying the working baseline

What code is known to work before the updates?

#### Ghidra fork

Most plugins would use a Ghidra source release as a baseline.  We need a source release
with additional RISC-V SLEIGH definitions, so our baseline is a branch of a Ghidra fork.

There are multiple Ghidra Git repository branches to track:

* The official Ghidra master branch at
  [git@github.com:NationalSecurityAgency/ghidra.git](git@github.com:NationalSecurityAgency/ghidra.git).
* A fork of the master branch at
  [git@github.com:thixotropist/ghidra.git](git@github.com:thixotropist/ghidra.git).
  The master branch of this fork is usually rebased to the official master branch at releases
  and occasionally between releases.
* A Ghidra branch holding RISC-V Instruction set extensions as the `isa_ext` branch of
  [git@github.com:thixotropist/ghidra.git](git@github.com:thixotropist/ghidra.git).
  This branch should closely track the master branch in the same repository.
* The branch `isa_ext_patched` which holds reference copies of the decompiler patches.
  This branch should closely track the `isa_ext` branch in the same repository.
  It is not itself a buildable Ghidra.  Instead, it is used to generate the `ghidra.pat` file.

The working baseline involves download the isa_ext branch at the commit shown below, then
building and installing it locally - in our case at `/opt/ghidra_12.2_DEV`.

```text
commit 08d62e52ede2bfe2768ab6fd5e14026389ed5e80 (HEAD)
Merge: 8164ab1e70 74d498f8da
Author: thixotropist <thixotropist@proton.me>
Date:   Sun Jun 14 17:37:26 2026 -0400
    Merge branch 'master' into isa_ext
commit 74d498f8da7d13f84604f531d59cb0cac028d6b2
Author: Ryan Kurtz <ryanmkurtz@users.noreply.github.com>
Date:   Fri Jun 12 05:31:46 2026 -0400
    GP-0: PE NumberOfSections is now properly unsigned (Closes #9166)
```

The Ghidra GUI and SLEIGH definitions are now available under `/opt/ghidra_12.2_DEV`.
We want to replace the `decompile` and `decompile_datatest` components, so the final step
is to make sure the current user (e.g. `thixotropist`) has write access to
`/opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/`.

#### Plugin framework

The integration test passes with this commit from `ghidra_decompiler_plugins`:

```console
$ git remote -v
origin	git@github.com:thixotropist/ghidra_decompiler_plugins.git (fetch)
origin	git@github.com:thixotropist/ghidra_decompiler_plugins.git (push)
$ git log
commit 4d82d1e46247568f7d256bf86d0d6a6204f11786 (HEAD -> main, origin/main, origin/HEAD)
Author: thixotropist <thixotropist@proton.me>
Date:   Sat Aug 15 16:53:53 2026 -0400
    Add a new test based on RISC-V C intrinsics
    Odd things can happen with complex loops.
```

#### integration_test.py

The integration test starts by:
* Downloading the baseline Ghidra source distribution branch (`isa_ext`), patching it with
  the `ghidra.pat` file, and caching the result.
* Compiling patched decompiler source code into an object library.
* Building `decompile` as the C++ executable spawned by the Ghidra GUI to decompile
  individual functions.
* Building `decompile_datatest` as the C++ executable used to exercise data-driven tests of the
  decompiler without requiring the Ghidra GUI to be running.

We use the bazelisk build system rather than CMake or Make, mostly for local preference.

```console
$ ./integrationTest.py
INFO:root:Cleaning the executable directory /opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/
INFO:root:Running rm -f /opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile
INFO:root:Running rm -f /opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest
INFO:root:Running bazelisk build -c opt @ghidra//:decompile
INFO:root:Running bazelisk build -c dbg @ghidra//:decompile_datatest
.INFO:root:Removing any previous plugin
INFO:root:Running rm -f /tmp/libriscv_vector.so
...
======================================================================
FAIL: test_04_failing_exemplars (__main__.T1Datatests.test_04_failing_exemplars)
Run failing tests to isolate common faults..
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/tmp/ghidra_decompiler_plugins/./integrationTest.py", line 300, in test_04_failing_exemplars
    self.assertTrue(all_tests_successful,
    ~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^
                     "At least one deferred test returned a non-zero exit code")
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: False is not true : At least one deferred test returned a non-zero exit code

----------------------------------------------------------------------
FAILED (failures=1)
```

That's a successful test run, since the only failures were in the test cases deferred until
after another Ghidra decompiler PR is merged.

## Surveying for decompiler changes

How  has the decompiler API changed in the weeks since the last rebase?  We can get a
rough view by applying `git diff` to the decompiler source header files:

```console
.../Ghidra/Features/Decompiler/src/decompile/cpp$ git diff 48f4c0b040456b99c3de84685657bed1d4a0f390..isa_ext *.hh
```

A quick scan indicates:

* A new `Architecture::max_baddata` member indicating an exception thrown if too many instructions can't be decoded.
* new classes `BlockIfElse`, `BlockIfNoExit`, `BlockIfGoto` derived from the existing `BlockIf`.
* multiple methods removed from `BlockIf` that are only useful in one of the derived classes.
* parameter replacement of various `Symbol` references with `Map` references
* parameter replacement of various `SymbolEntry` references with `DynamicEntry` references.
* a new decompiler remote command `DestinationOverride`
* multiple changes to `overide.hh`
* Documentation of `pcodecompile.hh`
* new `printRaw` methods for `TypeOp` classes
* some `Varnode` flags have changed

Update `MODULE.bazel` to refer to the rebased `isa_ext` commit and try `integration_test.py`.
If fails due to plugin compilation errors, since `BlockIf` no longer has a `getGotoTarget`
method.  There are likely other issues, but that's one we need to resolve first.

## Performing the rebase

Updating plugin framework code during a rebase operation can take several phases, depending
on how much the decompiler has changed since the last rebase.

The first thing to change is always the `isa_ext` baseline commit in `MODULE.bazel`.

```python
git_repository(
    name = "ghidra",
    remote = "git@github.com:thixotropist/ghidra.git",
    # This commit should be within the "isa_ext" branch
    commit = "6e9da93f3a5cd26102ee0d413cef2e21f1a369a8",
    build_file = "//:BUILD.ghidra",
    patches = ["ghidra.pat"],
    patch_strip = 1,
)
```

If nothing much has changed with decompiler code, the integration test
may run successfully.  If not, follow this sequence to complete the rebase.

### update the ghidra.pat file

Bazel - running under the `bazelisk` wrapper - will first download the named commit
and attempt to patch it with the `ghidra.pat` file. This will fail if there are conflicting
changes.  In this instance the API changes involving `block.hh` file and the `BlockIf` class
hierarchy are more than enough to fail the patch.

Updating `ghidra.pat` takes these steps:

1. In the local Ghidra repo, checkout the `isa_ext_patched` branch and merge the updated
  `isa_ext` branch into it. Resolve any conflicts.
2. Generate a new `ghidra.pat` file with `git diff isa_ext..isa_ext_patched > /tmp/ghidra.pat`
3. Replace `ghidra.pat` with`/tmp/ghidra.pat`
4. Clean cached artifacts like the previous patched Ghidra with `bazelisk clean --expunge`
5. Exercise the patch and attempt building a patched decompiler with `bazelisk build -c opt @ghidra//:decompile`

If the patch is applied successfully you should see the patched Ghidra distribution
in your workspace under `bazel-ghidra_decompiler_plugins/external/+git_repository+ghidra`.

The patched decompiler may or may not compile successfully at this point.  If it does,
skip the next step.

### updating the BUILD.ghidra file

Bazel needs dependencies explicitly named in the `BUILD.ghidra` file.  If the decompiler
includes new or renamed source files, `BUILD.ghidra` should be updated and the build
reattempted.  The patched Ghidra distribution will have been successfully cached, so
no additional downloads are needed.

### updating the plugin code

After building and installing patched `decompile` and `decompile_datatest` executables,
the integration test will attempt to build the RISC-V plugin.  In this instance, the
build will fail because the decompiler API has changed since the last rebase -
`BlockIf::getGotoTarget` has been removed and `BlockIf` now has three derived classes
handling variants.  The plugin `Inspector` class needs to know how to log the new classes
and the plugin `FunctionEditor` class needs to know how process `replaceBlock` method calls
on the new class objects.

Iterate on plugin code changes until `bazelisk build -c dbg plugins:riscv_vector` reports
success.

### iterated integration tests

Now we can start running the integration tests and look for regressions - or additional
tests to add.

We see these failing test cases:

* `whisper_sample_4` and `whisper_sample_12` - fail with
  ` Bad instruction count exceeded ... Unable to resolve constructor:` and no  appreciable plugin activity logged
* `dpdk_sample_8` - fails with `Low-level ERROR: Free varnode has multiple descendants`

We can isolate and repeat these tests at the command line with invocations like
```console
$ SLEIGHHOME=/opt/ghidra_12.2_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so \
  /opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < \
  test_data/whisper_sample_4.ghidra
```

Let's repeat the `whisper_sample_4` with no plugin:

```console
$ SLEIGHHOME=/opt/ghidra_12.2_DEV/ \
  /opt/ghidra_12.2_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < \
  test_data/whisper_sample_4.ghidra
```

So this problem lies with either the patched `decompile_datatest` or `test_data/whisper_sample_4.ghidra`.

Start Ghidra with the plugin loaded and inspect the function on which `test_data/whisper_sample_4.ghidra` is based.
This is a ~3000 line decompilation that takes a fair amount of time to decompile.

```console
DECOMP_PLUGIN=/tmp/libriscv_vector.so ghidraRun
```

Differential testing suggests that the problem is with the test case, not the patched decompiler or the plugin.
The `whisper_sample_4.ghidra` binary refers to a string at 0x103668, but these bytes are not captured in a
`bytechunk`.  Instead, their nature is captured in a `<mapsym><symbol>...</symbol></mapsym>` stanza in a freshly
exported debugging XML file.  The likely fix is to restore some of these missing symbols.

The fix looks easy - regenerate the `*_save.xml` files for all three failing tests, making sure to include mapped
symbols this time.  The integration tests find a few more vector_* transforms, likely because function call signatures
are definite enough to rule out inclusion of vector loop temporaries.

At this point the integration test passes.  We're not done yet, since we have no code to log the new Block objects.
We need to reduce the number of warnings logged, and to help identify any future blocks where other `BlockIf*` derived classes
refer to vector loops we are transforming.  For now, just treat the new block classes like other blocks with subblock components,
and log an informational message as a reminder.
