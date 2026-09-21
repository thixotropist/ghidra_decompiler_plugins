---
title: Running survey analyses
description: Surveys can help prioritize the next steps when analyzing an executable
weight: 30
---

>Note: This page summarizes *tentative* conclusions made from surveys posted as of
>      July 2026.  The organization of these conclusions needs some editorial work.

* RISC-V vector transforms of sequences like `memset`, `memcpy`, `strlen`, and `strcmp` are
  common in executables built under the RVA23 profile, even when the application does not
  appear to have much to do with vector processing.
    * The frequency of vector instructions is likely in the range of 5% to 10%.
* Vector sequences that involve `LMUL>1` or that request unchanged tail or unmasked elements are
  currently quite rare.  That's good, since these materially confuse the decompiler's heritage
  calculations.
* The list of `unhandled` vector instructions is quite varied, but perhaps limited enough to
  prioritize external review of what the instructions actually do.
    * for example, the vector id, gather, slide, and population count instructions occur fairly
      often.
* Many vector sequences and loops involve width conversions, complicating recognition and
  analysis.
* There are few immediately obvious transforms matching C++ `reduce` or `transform` functional
  forms.  These exist, but the rules for extracting lambda expressions from the compiled code
  look difficult.
* Optimization level `-O3` produces some very complex block diagrams of limited apparent utility.
  Don't chase after this type of transform with compilers similar to gcc 15 or earlier.
    * These optimizations may improve as more RISC-V RVA23 cores come into use and can provide
      tuning data to compare memory access times with instruction times and branch delays.