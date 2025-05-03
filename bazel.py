"""
Collect material needed to use Bazel in an integration test setting.
"""

import os
import logging
import subprocess

class Bazel():
    """
    Collect Bazel build system commands, options, and possibly tests.
    Available options:
    * 'no_bazelrc' : Ignore the contents of the local `.bazelrc`
    * 'output_base': all artifacts are generated here, likely a RAMFS
    * 'distdir': a local cache directory for Bazel components,
    * 'toolchain_resolution': enable platform to toolchain resolution,
    * 'bzlmod': import external BzlMod modules like glog and gtest,
    * 'no_pic': disable Position Independent Code generation
    * 'save_temps': save temporary files generated during compilation, e.g., assembly source code
    * 'show': show how each object is generated
    * 'resolution_debug': debug platform to toolchain resolution
    * 'opt': compile with optimization,
    * 'dbg': compile with debugging symbols

    Common Bazel invocations:

    * `BUILD_HOST` build on the host computer with the host's default platform and toolchain
    * `BUILD_PLATFORM` build on the host computer with an explicit, imported platform and toolchain
    """

    options = {
        'no_bazelrc' : "--noworkspace_rc",
        'output_base': f"--output_base=/run/user/{os.getuid()}/bazel",
        'distdir': "--distdir=/opt/bazel/distdir",
        'toolchain_resolution': "--incompatible_enable_cc_toolchain_resolution",
        'bzlmod': "--experimental_enable_bzlmod",
        'no_pic': "--features=-supports_pic",
        'save_temps': "--save_temps",
        'show': "-s",
        'resolution_debug': "--=toolchain_resolution_debug\'.*\'",
        'opt': "--compilation_mode=opt",
        'dbg': "--compilation_mode=dbg",
        'global_repo': "--registry=https://bcr.bazel.build",
        'local_repo': "--registry=file:///opt/bazel/bzlmod",
        # add an early 7.0.0 bazel workaround
        'hack': "--incompatible_sandbox_hermetic_tmp=false"
    }
    # a successful build is reported with this string
    BUILD_SUCCESS_PATTERN = 'Build completed successfully'

    # Define common bazel build and test commands here
    #   be careful with the separating spaces here - we need exactly one blank between options
    BASE_COMMAND = f"bazel {options['no_bazelrc']} {options['output_base']}"
    BUILD_HOST = BASE_COMMAND + f" build {options['distdir']}"
    BUILD_PLATFORM = BASE_COMMAND + f" build {options['distdir']} {options['toolchain_resolution']}"
    TEST_HOST = BASE_COMMAND + \
        f" test {options['distdir']} {options['toolchain_resolution']} {options['bzlmod']}"

    def __init__(self, logger=logging):

        self.logger = logger

    def execute(self, platform, target, operation='build', mode=None, copt=None, save_temps=False):
        """
        Build a target with the given platform using toolchain resolution.
        the target parameter may either be a single string or a list of strings
        """
        command = ['bazel',                                 # invoke bazel
                    Bazel.options['no_bazelrc'],            #   ignoring .bazelrc
                    Bazel.options['output_base'],           #   with output redirected
                    operation,                              # request a build or a test
                    Bazel.options['global_repo'],           #   using the global Bazelmod repo
                    Bazel.options['local_repo'],            #   and a local filesystem Bazelmod repo
                    '-s',                                   #   showing the compiler arguments
                    Bazel.options['distdir'],               #   into a local distribution cache

                    f'--platforms={platform}'               #   specifying the platform
                    ]
        if copt is not None:
            command.append(f'--copt={copt}')
        if mode is not None:
            command.append(f'--compilation_mode={mode}')
        if save_temps:
            command.append('--save_temps')
        if isinstance(target, str):
            command.append(target)
        else:   # concatenate a list of targets
            command.extend(target)
        self.logger.info("Running: %s", ' '.join(command))
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            self.logger.error("Bazel build failed:\n %s", result.stderr)
        return result

    def query(self, query_text):
        """
        Run a bazel query
        """
        command = ['bazel', 'query', query_text]
        self.logger.info("Running: %s", ' '.join(command))
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            self.logger.error("Bazel build failed:\n %s", result.stderr)
        return result
