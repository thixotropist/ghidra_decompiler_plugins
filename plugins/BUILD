cc_library(
    name = "riscv_vector",
    srcs = [
        "inspector.hh",
        "inspector.cc",
        "riscv.hh",
        "riscv.cc",
        "rule_vector_transform.hh",
        "rule_vector_transform.cc",
        "vector_matcher.hh",
        "vector_matcher.cc",
        "framework.hh",
        "framework.cc",
        "vector_ops.hh",
        "vector_ops.cc",
    ],
    copts = [
        "-Wno-sign-compare",
    ],
    deps = [
        "@ghidra//:decomp_lib",
        "@spdlog//:spdlog",
    ],
)