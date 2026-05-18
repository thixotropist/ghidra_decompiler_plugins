---
title: Refactoring
description: The quest to make spaghetti code look like something well designed
weight: 90
---

We want to clarify the design and code so that the next round of experiments has a better foundation.
This will include:

1. Identify and migrate functions into their appropriate namespaces and files.  Ghidra utilities should
   be moved into `framework` and `inspector` files, processor-specific general functions into `riscv*` files,
   vector specific transforms into `vector*` files, and possibly individual vector patterns and transforms
   into specialist files - perhaps aggregating any stdlib functions into  `vector_stdlib` files.
2. Reduce the amount of ad hoc feature extraction used for each transform, making transforms simpler than
   `vector_strcmp` look like subsets of the `vector_strcmp` detailed coding.  For instance, isolating result
   fields from epilogs might be handled by tracing dependency intersections throughout the code.
3. Reduce the amount of ad hoc or unused code in `vector_matcher`, moving it to `vector_ops` or `framework` files.
4. Collect logging diagnostics, so that they are not replicated in every transform.

The current snapshot has this code distribution, as determined by `sloccount`:

| file | Lines of code |
| ---- | ------------- |
| inspector, framework | 459⇒494 |
| riscv*, vector* | 2,333⇒2,103 |
| total           | 2,792⇒2,597 |
