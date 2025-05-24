cc_library(
    name = "riscv_vector",
    srcs = [
        "diagnostics.hh",
        "diagnostics.cc",
        "riscv.hh",
        "riscv.cc",
        "vector_transformer.hh",
        "vector_transformer.cc",
        "vector_matcher.hh",
        "vector_matcher.cc",
        "utility.hh",
        "utility.cc",
    ],
    copts = [
        "-Wno-sign-compare",
    ],
    deps = [
        "@ghidra//:decomp_lib",
        "@spdlog//:spdlog",
    ],
)