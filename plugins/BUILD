cc_library(
    name = "riscv_vector",
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
        "vector_matcher.hh",
        "vector_matcher.cc",
        "vector_ops.hh",
        "vector_ops.cc",
        "vector_stdlib.cc",
    ],
    copts = [
        "-Wno-sign-compare",
        "-std=c++20"
    ],
    deps = [
        "@ghidra//:decomp_lib",
        "@spdlog//:spdlog",
    ],
)