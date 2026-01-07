load(":gcc/cc_toolchain_config.bzl", "cc_toolchain_config")
load("//:variables.bzl", "OUTPUT_BASE")

package(default_visibility = ["//visibility:public"])

# These should match a dependency named in MODULE.bazel
SUITE_MODULE = "gcc_riscv_suite"

# This is the gcc version, not the bazel gcc_riscv_suite module version
SUITE_VERSION = "15.2.0"

# the binutils, gcc, and glibc configuration target
SUITE_TARGET = "riscv64-linux-gnu"

# Bazel currently makes the imported module available at this file system location
PATH_TO_MODULE = OUTPUT_BASE + "/external/" + SUITE_MODULE + "+"

# compiler and linker need to know the imported location of sysroot
SYSROOT = "external/" + SUITE_MODULE + "+/"

# a generic RISCV 64 hart supporting the rva23 ISA profile
constraint_value(
    name = "riscv64",
    constraint_setting = "@@platforms//cpu",
)

filegroup(
    name = "empty",
    srcs = [],
)

filegroup(
    name = "gcc_riscv_objdump",
    srcs =
        [
            "gcc/wrappers/objdump",
        ],
)

# Most compiler and linker actions depend on an imported gcc, local wrappers, and loader scripts
filegroup(
    name = "gcc_riscv64_compiler_files",
    srcs =
        glob(["gcc/wrappers/*"]) + [
            "gcc/elf64lriscv.xc",
            "gcc/elf64lriscv.xdc",
            "@gcc_riscv_suite//:compiler_files",
        ],
)
# The toolchain configuration uses a slightly customized rule allowing for
# multiple machine architecture toolchain definitions
cc_toolchain_config(
    name = "riscv64-rva23-gcc-config",
    march = "rv64gcv_zfh_zba_zicbop",
)

cc_toolchain(
    name = "riscv64-rva23-gcc",
    all_files = ":gcc_riscv64_compiler_files",
    compiler_files = ":gcc_riscv64_compiler_files",
    dwp_files = ":empty",
    linker_files = ":gcc_riscv64_compiler_files",
    as_files = ":gcc_riscv64_compiler_files",
    ar_files = ":gcc_riscv64_compiler_files",
    objcopy_files = ":gcc_riscv64_compiler_files",
    strip_files = ":gcc_riscv64_compiler_files",
    supports_param_files = 0,
    toolchain_config = ":riscv64-rva23-gcc-config",
    toolchain_identifier = "riscv64-rva23-gcc",
)

# currently selected with the riscv64 platform
toolchain(
    name = "riscv64-rva23",
    exec_compatible_with = [
        "@@platforms//cpu:x86_64",
        "@@platforms//os:linux",
    ],
    target_compatible_with = [
        ":riscv64",
    ],
    toolchain = ":riscv64-rva23-gcc",
    toolchain_type = "@@bazel_tools//tools/cpp:toolchain_type",
)
