---
title: Integration Test Suite
description: The integration test suite, driven by `integrationTest.py`, exercises the decompiler with binaries packaged as Ghidra datatests.
weight: 60
---

Datatests are a native capability of the Ghidra decompiler, running independently
of the Ghidra Java system and GUI.  Test cases live in the `./test` directory and generally consist of
an XML save file and a Ghidra test script.

This page describes each of the tests and what a successful test should generate.

## memcpy_exemplars

This test provides five minimalist `vector_memcpy` patterns, each contained within its own function.
Four of these are loop-free patterns where the number of elements to copy is fixed at compile time.  The fifth
is a loop pattern where the number of elements to copy is passed as a parameter.  The block structure is
also minimal.  There are no other vector instructions to test for false matches.  This test appears
within `integrationTest.py` as `T1Datatests.test_01_memcpy_exemplars`.

## whisper_sample_1

This test imports the std::string_constructor.  The function includes one `vector_memcpy` stanza and one
`vector_strlen` stanza.  The `vector_memcpy` is recognized correctly.  The `vector_strlen` transform is not
yet implemented.  The C decompilation around `vector_memcpy` shows an unnecessary `do ... while` block.
The Phi node calculation is flawed, as the first parameter to `vector_memcpy` has an incorrect heritage.

## whisper_main

The Whisper main routine contains both `vector_memcpy` and `vector_memset` stanzas.  It includes extensive
stack variable definitions and a complex block structure.

## whisper_sample_2

This is the `drwav_u8_to_s32` function.  It includes a vector stanza that is should not match any of the defined
vector transforms.

## whisper_sample_3

This is the `quantize_row_q8_K_ref` function.  It includes several `vector_memcpy` fixed length transforms and
a complex unrelated vector stanza.

## whisper_sample_4

This test throws a decompiler exception with or without a plugin present.  A malformed savefile is suspected but
not proven.  The test function is `whisper_model_load`, which decompiles properly within the full Ghidra system.
This function appears to contain several `vector_memcpy` stanzas.

## whisper_sample_5

This is the `whisper_wrap_segment` function.  It includes multiple `vector_memset` and `vector_memcpy` transforms

## whisper_sample_6

This is the `drwav_f32_to_s16` function.  It includes unrelated and partially implemented user pcodeops to test
regressions.

## whisper_sample_7

This is the `quantize_q4_0` function. It currently throws the `Low-level ERROR: Free varnode has multiple descendants` error.

## whisper_cpp_rva23

This test is not part of `integrationTest.py`.  It uses the Ghidra GUI to import the entire program, then export
it as a C/C++ source file.

* 468 `vector_memcpy` transforms
* 1111 `vector_memset` transforms
* 0 decompiler process failures
