# Overview

The bulk of this project's documentation is structured as a Hugo + Docsys static web site,
with source material collected under `content/en`. Local browsing is enabled with `hugo serve`.

The intended audience includes Ghidra users wishing to extend or research Ghidra's decompiler subsystem,
especially in support of instruction set architecture extensions like the RISC-V vector instruction set.

This is a research project intended to show what *may* be done with the Ghidra decompiler and at what complexity.
We can avoid the complexity of full Ghidra decompiler PR reviews by proposing no enduring changes to the decompiler
itself.  Instead, the first decompiler plugin build triggers a download of Ghidra sources, which are patched to provide a minimal
plugin manager.  Exploratory development then proceeds within the plugin, using the decompiler's native datatest framework for
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
