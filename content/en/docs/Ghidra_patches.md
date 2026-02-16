---
title: Ghidra Patches
weight: 70
---

Ghidra decompiler plugins need support within the decompiler.  This support is installed
via the `ghidra.pat` patch file in the top directory applied to a released Ghidra distribution.
This patch file currently provides:

* Invocation of the `PluginManager` with changes to `architecture.hh` and `architecture.cc`.
* New `BlockGraph` methods to `block.hh` and `block.cc` to edit a function's displayed C control
  structure.
* The `PluginManager` class to:
    * initialize and terminate plugins via runtime shared library modules
    * import plugin Rules
    * register any plugin datatyped builtins - like `vector_memcpy`
* Import one or more new plugin Rules to the Cleanup Action in `coreaction.cc`
* Add the [spdlog](https://github.com/gabime/spdlog) logging subsystem to the Ghidra decompiler
  to support exploratory development and help resolve dependency/lifetime issues.
    * C++20 is likely required to provide the `std::format` library used by spdog.

  >Warning: These patches have only been tested with gcc 15 on a Linux platform.  Other platforms
  >         will require dynamic library mods to the `PlatformManager`.

  ## Limitations

  * There is no current support for unloading a plugin once loaded.  The issue involves deletion of all *copies* of
    plugin rules before the plugin rule destructor code is unlinked. In practice this isn't much of a problem, as
    the Ghidra GUI will restart and reload the decompiler itself.