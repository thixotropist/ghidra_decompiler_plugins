load("@rules_cc//cc:cc_library.bzl", "cc_library")

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
