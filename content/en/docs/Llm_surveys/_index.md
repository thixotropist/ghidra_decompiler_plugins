---
title: Large Language Model Surveys
linkTitle: LLM Surveys
description: |
  An experimental set of AI-generated responses to queries a Ghidra user/developer might generate, for instance a query on how
  other decompiler frameworks than Ghidra deal with similar challenges.  The accuracy of some of these responses is questionable,
  so they may be best used as suggestions for broader investigations.
weight: 980
---

Google's Antigravity and Gemini tooling can provide interesting - and maybe even useful -
summaries of related technology.  Nothing in this directory should be taken as fact without
verification.

## Commentary

### Drone vendors

The [Drone vendors]({{< relref "Drone_vendors.md" >}}) survey simply tests some of our framing assumptions.
We assumed that AI-enhanced drones or drone controllers would find RISC-V processors attractive.
This query attempts to substantiate that assumption, and to identify which vendors might
be taking the lead in such implementations.

The response suggests that drone vendors are likely to be using ARM processors today and to be
evaluating RISC-V alternatives.  If so, that might set up a good architectural test case for
Ghidra:

* ARM's Scalable Vector Extension and RISC-V's vector extensions are both vector length agnostic.
  They have different designs and microarchitectures.  Which of those features are held in common
  and reasonable to incorporate into Ghidra directly, and which would be better factored into
  processor-specific plugins?

### RVV decompiler survey

Ghidra is not the only decompiler available.  How do some of the others handle RISC-V vector
extensions?  The [RVV decompiler]({{< relref "RVV_decompiler_survey.md" >}}) survey asks that
question.

The [binary ninja](https://binary.ninja/) approach looks somewhat similar to our approach, especially if we consider the
'pcode-explosion' as resolved by partitioning into architecture-specific plugins and user pcodeOps as closer to intermediate language tokens to process after loop analysis.

The [IDA Pro](https://hex-rays.com/ida-pro) approach looks to concentrate on translating to C intrinsic functions.  That's worth
looking into.  A big challenge there is to cope with the vast number of RISC-V C instrinsic
functions, all differentiated by type information that may or may not be available within
the decompiler.

### RISC-V intrinsic functions

IDA Pro apparently translates vector instructions into C intrinsic functions.  There are a lot of
them, according to a [RISCV Intrinsic]({{< relref "RISCV_intrinsic_functions.md" >}}) survey.
As many as 100,000, due to all of the type and context combinatorics involved.

### Debugging GCC with Ghidra

The current GCC compiler can miscompile code that uses many RISC-V instrinsic functions within a large and complex loop.
This [survey]({{< relref "Gcc16_riscv_bugs.md" >}}) explores how far the community may be towards fixing that problem.