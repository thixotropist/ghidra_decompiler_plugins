# See external/rules_cc+/cc/private/toolchain/cc_toolchain_config.bzl for rules on how to generate
# Note:  The Bazel developers are slowly migrating the cc rules from bazel_tools to rules_cc.
#        Action names here likely to change
load("@@bazel_tools//tools/build_defs/cc:action_names.bzl", "ACTION_NAMES")
load(
    "@@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    "feature",
    "flag_group",
    "flag_set",
    "tool_path",
    "with_feature_set",
)

# Paths are user dependent - we need the path to Bazel's OUTPUT_BASE
load("//:variables.bzl", "OUTPUT_BASE")

# gcc is called as a linker to implement at least these actions
all_link_actions = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

# gcc is called as a compiler to implement at least these actions
all_compile_actions = [
    ACTION_NAMES.c_compile,
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.linkstamp_compile,
    ACTION_NAMES.assemble,
    ACTION_NAMES.preprocess_assemble,
    ACTION_NAMES.cpp_header_parsing,
    ACTION_NAMES.cpp_module_compile,
    ACTION_NAMES.cpp_module_codegen,
    ACTION_NAMES.clif_match,
    ACTION_NAMES.lto_backend,
]

# Collect some toolchain-specific identifiers that will appear
# many times in this CcToolchainConfigInfo

# These should match a dependency named in MODULE.bazel
SUITE_MODULE = "gcc_riscv_suite"

# This is the gcc version, not the bazel gcc_riscv_suite module version
SUITE_VERSION = "15.2.0"

# the binutils, gcc, and glibc configuration target
SUITE_TARGET = "riscv64-linux-gnu"

# Bazel currently makes the imported compiler suite available at this file system location
PATH_TO_MODULE = OUTPUT_BASE + "/external/" + SUITE_MODULE + "+"

# Generate the set of sandbox filesystem directories containing system include files
# that need inclusion on gcc command lines.  Be wary of sequencing as the '#include_next
# preprocessor directive is sequence-dependent
SYSTEM_INCLUDE_FLAGS = [
    "-isystem" + PATH_TO_MODULE + "/lib/gcc/" + SUITE_TARGET + "/" + SUITE_VERSION + "/include-fixed",
    "-isystem" + PATH_TO_MODULE + "/lib/gcc/" + SUITE_TARGET + "/" + SUITE_VERSION + "/include",
    "-isystem" + PATH_TO_MODULE + "/" + SUITE_TARGET + "/include/c++/" + SUITE_VERSION,
    "-isystem" + PATH_TO_MODULE + "/usr/include/" + SUITE_TARGET,
    "-isystem" + PATH_TO_MODULE + "/usr/include",
]

# Generate the set of sandbox filesystem directories that might be found as dependencies after 'gcc -MD -MF ... helloworld.d'
# header scanning
SYSTEM_INCLUDE_DIRS = [
    PATH_TO_MODULE + "/lib/gcc/" + SUITE_TARGET + "/" + SUITE_VERSION + "/include-fixed",
    PATH_TO_MODULE + "/lib/gcc/" + SUITE_TARGET + "/" + SUITE_VERSION + "/include",
    PATH_TO_MODULE + "/" + SUITE_TARGET + "/" + "/include/c++/" + SUITE_VERSION,
    PATH_TO_MODULE + "/usr/include/" + SUITE_TARGET,
    PATH_TO_MODULE + "/" + SUITE_TARGET + "/sys-include",
    PATH_TO_MODULE + "/usr/include",
]

# generate the structure implementing cc_toolchain_config
def _impl(ctx):
    tool_paths = [
        tool_path(
            name = "gcc",
            path = "gcc/wrappers/gcc",
        ),
        tool_path(
            name = "ld",
            path = ":empty",
        ),
        tool_path(
            name = "ar",
            path = "gcc/wrappers/ar",
        ),
        tool_path(
            name = "as",
            path = "gcc/wrappers/as",
        ),
        tool_path(
            name = "cpp",
            path = "gcc/wrappers/cpp",
        ),
        tool_path(
            name = "gcov",
            path = ":empty",
        ),
        tool_path(
            name = "nm",
            path = "gcc/wrappers/nm",
        ),
        tool_path(
            name = "objdump",
            path = "gcc/wrappers/objdump",
        ),
        tool_path(
            name = "strip",
            path = "gcc/wrappers/strip",
        ),
    ]
    opt_feature = feature(name = "opt")
    dbg_feature = feature(name = "dbg")
    supports_pic_feature = feature(
        name = "supports_pic",
        enabled = True,
    )
    pic_feature = feature(
        name = "pic",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.cpp_module_compile,
                ],
                flag_groups = [
                    flag_group(flags = ["-fPIC"], expand_if_available = "pic"),
                ],
            ),
        ],
    )
    force_pic_flags_feature = feature(
        name = "force_pic_flags",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.cpp_link_executable,
                    ACTION_NAMES.lto_index_for_executable,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["-pie"],
                        expand_if_available = "force_pic",
                    ),
                ],
            ),
        ],
    )

    features = [
        feature(
            name = "default_compile_flags",
            enabled = True,
            flag_sets = [
                flag_set(
                    actions = all_compile_actions,
                    flag_groups = ([
                        flag_group(
                            flags = SYSTEM_INCLUDE_FLAGS + [
                                "-march=" + ctx.attr.march,
                                "-no-canonical-prefixes",
                                "-fno-canonical-system-headers",
                                "-Wno-builtin-macro-redefined",
                                "-D__DATE__=\"redacted\"",
                                "-D__TIMESTAMP__=\"redacted\"",
                                "-D__TIME__=\"redacted\"",
                                "-fstack-protector",
                                "-Wall",
                                "-Wunused-but-set-parameter",
                                "-Wno-free-nonheap-object",
                                "-fno-omit-frame-pointer",
                            ],
                        ),
                    ]),
                ),
                flag_set(
                    actions = all_compile_actions,
                    # These flags are only used with the 'dbg' feature:
                    #    with '-c dbg' or '--features dbg' on the command line
                    flag_groups = [flag_group(flags = ["-g"])],
                    with_features = [with_feature_set(features = ["dbg"])],
                ),
                flag_set(
                    actions = all_compile_actions,
                    # These flags are only used with the 'opt' feature:
                    #    with '-c opt' or '--features opt' on the command line
                    flag_groups = [
                        flag_group(
                            flags = [
                                "-g0",
                                "-O2",
                                "-DNDEBUG",
                                "-ffunction-sections",
                                "-fdata-sections",
                                "-U_FORTIFY_SOURCE",
                                "-D_FORTIFY_SOURCE=1",
                            ],
                        ),
                    ],
                    with_features = [with_feature_set(features = ["opt"])],
                ),
                flag_set(
                    # These flags are only used when compiling c++:
                    actions = [
                        ACTION_NAMES.linkstamp_compile,
                        ACTION_NAMES.cpp_compile,
                        ACTION_NAMES.cpp_header_parsing,
                        ACTION_NAMES.cpp_module_codegen,
                        ACTION_NAMES.cpp_module_compile,
                        ACTION_NAMES.lto_backend,
                    ],
                    flag_groups = [flag_group(flags = ["-std=c++20"])],
                ),
            ],
        ),
        opt_feature,
        dbg_feature,
        supports_pic_feature,
        force_pic_flags_feature,
        feature(
            name = "default_link_flags",
            enabled = True,
            flag_sets = [
                flag_set(
                    actions = all_link_actions,
                    flag_groups = ([
                        flag_group(
                            flags = [
                                "-Wl,-Textras/toolchains/riscv/gcc/elf64lriscv.xc",
                                "-Wl,-lstdc++",
                                "-Wl,-lm",
                                "-Wl,-z,relro,-z,now",
                                "-no-canonical-prefixes",
                                "-pass-exit-codes",
                            ],
                        ),
                    ]),
                ),
                flag_set(
                    actions = all_link_actions,
                    flag_groups = [flag_group(flags = ["-Wl,--gc-sections"])],
                    with_features = [with_feature_set(features = ["opt"])],
                ),
            ],
        ),
    ]

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        features = features,
        cxx_builtin_include_directories = SYSTEM_INCLUDE_DIRS,
        toolchain_identifier = "local",
        host_system_name = "local",
        target_system_name = "local",
        target_cpu = "k8",
        target_libc = "unknown",
        compiler = "gcc",
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = tool_paths,
    )

cc_toolchain_config = rule(
    implementation = _impl,
    # allow the machine architecture to be a named attribute of this rule
    attrs = {
        "march": attr.string(default='rv64gcv'),
    },
    provides = [CcToolchainConfigInfo],
)
