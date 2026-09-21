---
title: Futures
linkTitle: Futures and Evolutions
description: |
   A subjective analysis of how Ghidra's decompiler might evolve to handle similar
   processor-specific challenges.  More specifically, processor instructions which
   do not translate into current SLEIGH semantics.
weight: 40
---

{{% blocks/section color='white' %}}

This project explores Ghidra decompiler problems that will likely become critical
inside of four years.  Will finding solutions take two years - or ten?  We start with a
set of assumptions about the future Ghidra domain:

1. The decompiler code will continue to evolve slowly, with updates driven mostly by bug
   fixes rather than new features.
2. The decompiler build environment will continue to be grounded in older systems, such as
   RHEL 7.
3. Approvals for decompiler community Pull Requests for significant new features will
   require more developer resources than are available.
4. The broader Ghidra community will continue to propose SLEIGH extensions in support of
   instructions which do not have simple SLEIGH semantic sections.  RISC-V vector instructions
   are examples here, with multi-platform crypto and SIMD instruction PRs also proliferating.
5. Processor micro-architectures developed for AI, IE, or LLM applications will continue to
   evolve and diverge faster than the decompiler's SLEIGH semantic definitions.
6. These AI, IE, and LLM applications will directly benefit from vector instructions in obvious
   vector contexts - but the compilers will take advantage of the expanded register space and
   vector memory channels to replace many scalar instruction sequences with tuned vector
   sequences.




{{% /blocks/section %}}