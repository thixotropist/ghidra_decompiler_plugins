---
title: Bazel Notes
description: The Bazel build tool may need per-user configuration
weight: 80
---

The Bazel environment may need tuning when deployed.  This project's development host currently uses Bazel
release 9.1.1, and is expected to track the Bazel development tip fairly closely.  `bazelisk` is used on the command line
where `bazel` might be expected - `bazelisk` consults the `.bazelversion` file to choose the current version to download and run.

>Note: The Bazel development team is currently refactoring Bazel modules used in support of crosscompiler environments.
>      This refactoring is the primary driver for closely tracking the Bazel development tip.

Most Bazel environment parameters are set in the top level file `.bazelrc`.  This file currently contains:

```text
# Global Bazel flags
# Generate all Bazel artifacts in a RAM tmpfs owned by the user, in this case UID 1000
# This does not include imported packages
startup --output_base=/run/user/1000/bazel

# Allow for local caching of imported packages
build --distdir=/opt/bazel/distdir
# Add global registry
common --registry https://bcr.bazel.build
# Add local registry
common --registry file:///opt/bazel/bzlmod
```

Other users may want to alter the `startup` line.  The default case here assumes the user has a UID=1000 and
wants to construct all of the intermediate Bazel files in the `/run/user/$UID` RAM file system.  That speeds
incremental builds and reduces wear and tear on the system SSD storage, at the cost of a longer initial build and
increased RAM dedicated to the project.

The registry entries allow for Bazel modules to be loaded from either the default global module registry or from
the local file system.  Modules like the spdlog logging subsystem can be found in the global registry, while
RISC-V toolchains are found in the local registry.
