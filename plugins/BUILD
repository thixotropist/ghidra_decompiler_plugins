load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

cc_library(
    name = "riscv_vector",
    srcs = [
        "action_prepare.cc",
        "action_prepare.hh",
        "framework.cc",
        "framework.hh",
        "inspector.cc",
        "inspector.hh",
        "riscv.cc",
        "riscv.hh",
        "riscv_sleigh.cc",
        "riscv_sleigh.hh",
        "rule_vector_transform.cc",
        "rule_vector_transform.hh",
        "vector_matcher.cc",
        "vector_matcher.hh",
        "vector_ops.cc",
        "vector_ops.hh",
        #        "vector_instr_handlers.cc",
        "vector_stdlib.cc",
    ],
    copts = [
        "-Wno-sign-compare",
        "-std=c++20",
    ],
    deps = [
        "@ghidra//:decomp_lib",
        "@spdlog",
    ],
)

cc_test(
    name = "handlers",
    size = "small",
    srcs = [
        "action_prepare.hh",
        "action_prepare.cc",
        "framework.hh",
        "framework.cc",
        "inspector.hh",
        "inspector.cc",
        "riscv.hh",
        "riscv.cc",
        "riscv_sleigh.hh",
        "riscv_sleigh.cc",
        "rule_vector_transform.hh",
        "rule_vector_transform.cc",
        "vector_ops.hh",
        "vector_ops.cc",
        "vector_instr_handlers.cc",
        "vector_matcher.hh",
        "vector_matcher.cc",
        "test_handlers.cc",
    ],
    copts = [
        "-Wno-sign-compare",
        "-std=c++20",
    ],
    deps = [
        "@ghidra//:decomp_lib",
        "@googletest//:gtest_main",
    ],
)
