cc_library(
    name = "riscv_vector",
    srcs = [
        "riscv.cc",
        "vectorsequence.hh",
        "vectorcopy.hh",
        "vectorcopy.cc",
    ],
    copts = [
        "-std=c++11",
        "-Wno-sign-compare",
    ],
    deps = [
        "@ghidra//:decomp_lib"
    ],
)