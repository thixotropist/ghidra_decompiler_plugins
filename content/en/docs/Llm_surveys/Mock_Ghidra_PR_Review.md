---
title: Mock Ghidra PR Review
description: |
    We need to model the Ghidra core development team's plausible response to
    speculative decompiler extensions, especially those that implicitly force
    broader architectural choices.
weight: 50
---

## Question

**User:**
Generate a decision tree for use by the Ghidra development team while reviewing the Github pull request at https://github.com/NationalSecurityAgency/ghidra/pull/5778.
Assume that the primary reviewer is GhidorahRex with ryankurtz the lead of the contracted developers.
Assume also that the contracted developers are operating under a restrictive set of policies from their US Government contract.
The decision tree should further assume that accepting this pull request would move the overall Ghidra decompiler architecture down a specific path,
and that a Government policy on such architectural paths is not yet ready for public dissemination.

### Assistant

I have created a comprehensive review protocol and decision tree for the Ghidra development team regarding [PR #5778](https://github.com/NationalSecurityAgency/ghidra/pull/5778).

The full operational document has been generated in [`ghidra_pr5778_review_decision_tree.md`]({{< relref "ghidra_pr5778_review_decision_tree.md" >}}).

### Commentary

The graphical decision tree is:

{{< figure src=/docs/images/decision_tree.svg align="center" >}}
