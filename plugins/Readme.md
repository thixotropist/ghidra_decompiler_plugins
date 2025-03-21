# Plugins

Plugins are experimental.  We hope to evaluate the feasibility of both user-contributed and processor-specific plugins.
The initial goal is to extend @caheckman commits transforming pcode sequences into `builtin_memcpy` calls, translating
common RISCV-64 vector instruction sequences into `builtin_memcpy`, `builtin_strlen`, and other higher level calls.

## Status

The local decompiler build of `ghidra_test_dbg` is the only application currently enabled for plugins.  It must be compiled with
the `LOADABLE_PLUGINS` C++ preprocessor flag and linked with `-Wl,--dynamic-list=ghidra_test_dbg.ld`.

The plugin needs dynamic access to certain Ghidra symbols, named in `ghidra_test_dbg.ld`.  The utility `src/collect_dependencies.py` 
scans a plugin and generates an appropriate dynamic symbol list file.  This file must be indcluded in the linking of any Ghidra
application expected to load a plugin

This first plugin is loaded at the end of the `Architecture` constructor, and initialized after `Architecture::init` is called.

The next steps include:

* Stub out code to search for plugin locations, load one or more plugins, and close those plugins when the program architecture closes.
* Enable the plugin to operate within both `ghidra_test_dbg` and the `decompile` binary invoked from the Ghidra Java app.