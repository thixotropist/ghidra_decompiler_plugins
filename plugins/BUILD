cc_library(
    name = "riscv_vector",
    srcs = [
        "inspector.hh",
        "inspector.cc",
        "riscv.hh",
        "riscv.cc",
        "riscv_sleigh.hh",
        "riscv_sleigh.cc",
        "riscv_csr.hh",
        "riscv_csr.cc",
        "rule_vector_transform.hh",
        "rule_vector_transform.cc",
        "vector_matcher.hh",
        "vector_matcher.cc",
        "framework.hh",
        "framework.cc",
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