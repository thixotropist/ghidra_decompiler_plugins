cc_library(
    name = "riscv_vector",
    srcs = [
        "diagnostics.hh",
        "diagnostics.cc",
        "riscv.hh",
        "riscv.cc",
        "vectorcopy.hh",
        "vectorcopy.cc",
        "vector_loop_match.hh",
        "vector_loop_match.cc",
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