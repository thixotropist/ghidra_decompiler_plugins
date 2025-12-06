/**
 * @file plugins_doc.hh
 *
 * @mainpage Ghidra Decompiler Plugins
 * The Ghidra decompiler does most of the work in generating a human-legible C-like listing,
 * given a function's binary image and a SLEIGH directory of pseudocode.
 * It runs as a separate process spawned by Ghidra.  Coded in C++, it is one of the most
 * complex - or just obscure - components of the Ghidra ecosystem.
 *
 * That complexity makes baseline decompiler extensions hard to test and therefore hard to
 * merge into the master branch.  This project offers an *experimental* alternative by
 * patching a PluginManager into a released Decompiler source repo, then crafting
 * processor-specific plugins to enhance decompiler results.
 *
 * @section design Design
 *
 * Design goals and constraints are currently:
 * * Demonstrate plugin loading on Linux, deferring other Ghidra platforms
 * * Prioritize decompiler window clarity over emulation
 * * Avoid Pull Requests modifying the Ghidra Decompiler in favor of patches applied to a released Ghidra
 * * Defer any effort to fully unload a plugin and load an alternate plugin without restarting the Decompiler process
 * * Refactor plugin code into ghidra extensions and Processor-specific components, using namespaces to identify the origin of
 *   types and classes.
 * * Avoid rebuilding Ghidra or the baseline Decompiler for each plugin test iteration
 * * Integration testing uses the existing Decompiler datatest infrastructure, often under `valgrind` or `gdb` control.
 * * Allow `std::c++` function calls in the decompiler window if they better represent vectorized sequences
 *
 * The initial plugin explorations involve the RISC-V vector extensions, especially as applied to Inference Engine or
 * other Machine Learning/AI applications.  We'll use the `whisper-cpp` voice-to-text application as our first test case,
 * compiled with gcc 15 and the `whisper-cpp` recommended optimizations for a RISC-V 64 bit processor implementing the RVA23 instruction set extension profile.
 * A second test case explores vectorized embedded control structures, using the `dpdk-pipeline` application with significant vector byte manipulation but little
 * vector mathematics.
 * The Ghidra user is assumed to have an ELF executable binary and to be looking for possible malicious alterations or unrecognized vulnerabilities
 * in the application.  If they want emulation capability, they will use a RVA23-capable QEMU environment and not rely on Ghidra's emulator.
 *
 * @section framework Framework
 *
 * Framework components fall into these categories:
 *
 * * Tools to inspect Ghidra's runtime structures, such as PcodeOps, Varnodes, and Blocks
 * * Methods to insert new Ghidra structures
 * * Methods to edit Ghidra's control flow representation, such as the replacing `do ... while` loops with function calls
 *
 * @section things_to_do Things to do
 * @subsection architectural-todo Architectural
 * Recovering the `context` in which vector instructions execute is a hard problem.  Without accurate knowledge of the
 * runtime values of the vector status registers, there is often no single SLEIGH representation of vector instruction
 * semantics.  The `M` Multiplier status register field modifies the number of vector registers that are considered active
 * in any given instruction, modifying the Decompiler's Heritage and descendent calculations.  Without accurate Heritage calculations
 * Ghidra may make poor decisions on which register and memory locations are active, falsely marking key code or return values as `dead`.
 *
 * The proper way to address this may be to propagate changes to vector status registers using the same Phi node (Heritage) tracking
 * mechanism as is used with register and memory locations.  Until then, we will take the simpler heuristic of inferring the
 * compiler's implied context changes for any given pattern, treating vector context as a purely local and temporary concept.
 *
 * A related problem occurs with scalar register lifetime.  A compiler will often use scalar registers like `a0`, `a1`, and `a2` to hold temporaries
 * in vectorized loops, followed by function calls.  Ghidra will normally consider those registers as live, and so likely parameters
 * to the function call.  The current heuristic trims those dependencies, assuming the compiler *never* relies on side effects of vector
 * loop transformations.
 *
 * @subsection developers-todo Developer Todos
 *
 * - document cppcheck process with `cppcheck -q --enable=warning,style,performance,portability --platform=unix64 --cppcheck-build-dir=./cppcheck *.cc`
 * - follow [Google C++ style guide](https://google.github.io/styleguide/cppguide.html) where feasible
 * - follow [Cpp core guidelines](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md) where feasible
 *
 * @subsection incremental-todo Incremental
 * * refactor the existing code base to enable code re-use.
 * * add additional vectorized implementations of common glibc patterns like `strlen`
 */