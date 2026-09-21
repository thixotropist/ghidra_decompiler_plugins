---
title: Full Executable Surveys
linkTitle: Surveys
description: |
    Ghidra decompiler plugins can help generate surveys of binary executables.
    Building and analyzing current LLM and device control firmware examples can
    help train the Ghidra user in what to expect with future analyses.
weight: 10
---

A Ghidra plugin can transform executable applications into something more easily understood.
There's a persistent challenge though: What extensions to the existing plugin(s) are actually
likely to be useful?  We'll continue with the notional goal of pushing Ghidra development into
something that would be useful in AI drone firmware reverse engineering, using open source
component applications to represent different aspects of such a hypothetical system.

Note that these are anecdotal surveys, collected as snapshots at different times.  They
do not constitute strict differential analyses.  For instance, applications like `dpdk-l3fwd`
might have two surveys present, one with `-O3` optimization and one with `-O2` optimization.
A strict differential analysis would ensure that these build options were the only changes
between the two executables.  In fact, there are likely many small differences in source code,
compilation options, and manual Ghidra state updates.  Comparisons are likely still valid for
large-scale, general trends.
