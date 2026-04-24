#!/usr/bin/python3
"""
Verify the correctness of the RISC-V Vector transforms Ghidra plugin
  *  Run all tests with ./integrationTest.py
  *  Run a single test with something like
  *  `python integrationTest.py T1Datatests.test_04_exemplar_regression`
"""
import unittest
import subprocess
import logging
import os
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging

GHIDRA_INSTALL_DIR = "/opt/ghidra_12.1_DEV/"
DECOMPILER_DIR = GHIDRA_INSTALL_DIR + "Ghidra/Features/Decompiler/os/linux_x86_64/"
DECOMPILER_PATH = DECOMPILER_DIR + "decompile"
DATATEST_PATH = DECOMPILER_DIR + "decompile_datatest"
BAZEL_BUILD_DECOMPILER_PATH = "bazel-bin/external/+_repo_rules+ghidra/decompile"
BAZEL_BUILD_DATATEST_PATH = "bazel-bin/external/+_repo_rules+ghidra/decompile_datatest"
PLUGIN_LOAD_DIR = "/tmp/"
PLUGIN_NAME = "libriscv_vector.so"
PLUGIN_PATH = PLUGIN_LOAD_DIR + PLUGIN_NAME
TEST_DATA_DIR = "test_data"

# Regression tests are split into two sets.  The valgrind and faster tests run under valgrind,
# while the regular ones do not.
VALGRIND_TEST_SET = ("memcpy_exemplars", "whisper_sample_4")
REGULAR_TEST_SET = ("strlen_exemplars",  "strcmp_exemplars", "whisperInit",
                    "whisper_sample_1a", "whisper_sample_1b", "whisper_sample_2",
                    "whisper_sample_3", "whisper_sample_5", "whisper_sample_6", "whisper_sample_7",
                    "whisper_sample_8", "whisper_sample_10", "whisper_sample_11",
                    "whisper_sample_12", "whisper_sample_13a", "whisper_sample_13b",
                    "whisper_sample_14", "whisper_sample_15", "whisper_sample_16", "whisper_main",
                     "dpdk_sample_1", "dpdk_sample_2", "dpdk_sample_3")

# some tests currently fail, so defer these to their own test case
DEFERRED_TESTS = ("whisper_sample_5", "whisper_sample_12", "whisper_main",
                  "whisper_sample_15")
expected = {
    'memcpy_exemplars':  {'vector_memcpy':5},
    'strlen_exemplars':  {'vector_strlen':2},
    'strcmp_exemplars':  {'vector_strcmp':2},
    'whisperInit':       {'vector_memset':1, 'vector_memcpy':3},
    'whisper_sample_1a': {'vector_memcpy':1, 'vector_strlen':0},
    'whisper_sample_1b': {'vector_memcpy':1, 'vector_strlen':1},
    'whisper_main': {'vector_memset':4, 'vector_memcpy':13, 'vector_strlen':1},
    'whisper_sample_2': {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'whisper_sample_3':  {'vector_memcpy':5,},
    'whisper_sample_4':  {'vector_memset':16, 'vector_memcpy':85, 'vector_strlen':0},
    'whisper_sample_5':  {'vector_memset':3, 'vector_memcpy':20, 'vector_strlen':1},
    'whisper_sample_6':  {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'whisper_sample_7':  {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'whisper_sample_8':  {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'whisper_sample_10':  {'vector_memset':0, 'vector_memcpy':3, 'vector_strlen':0},
    'whisper_sample_11':  {'vector_strcmp':1},
    'whisper_sample_12':  {'vector_memset':2, 'vector_memcpy':7, 'vector_strlen':1},
    'whisper_sample_13a':  {'vector_memcpy':0},
    'whisper_sample_13b':  {'vector_memcpy':1},
    'dpdk_sample_1':  {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'dpdk_sample_2':  {'vector_memset':0, 'vector_memcpy':1, 'vector_strlen':0},
    'dpdk_sample_3':  {'vector_strlen':2},
}

def trim_output(result):
    """
   limit the amount of output displayed on a failed test
    """
    if len(result) > 800:
        result = result[0:800] +'...'

def extract_c(result):
    """
    isolate the decompiled C source from a single function test case
    """
    start = '[decomp]> print C'
    end = '[decomp]> print raw'
    test_results = result
    c_source = ""
    while True:
        # Find the index of the start substring
        idx1 = test_results.find(start)
        if idx1 == -1:
            break
        idx2 = test_results.find(end, idx1 + len(start))

        # Check if both delimiters are found and extract the substring between them
        if idx1 != -1 and idx2 != -1:
            c_source = c_source + test_results[idx1 + len(start):idx2]
            test_results = test_results[idx2 + 1:]
        else:
            break
    return c_source

def assert_expected_transform_count(self, name, result_output):
    """
    count the number of vector transforms in the C section of a testcase stdout
    :param testCase: the invoked unit test case
    :param name: the name identifying the expected results
    :param result_output: the process output from the decompilation
    """
    source = extract_c(result_output)
    if not name in expected:
        return
    expected_results = expected[name]
    for pat in expected_results:
        num_found = source.count(pat)
        print(f"found {num_found} instances of {pat} in test case {name}")
        if num_found != expected_results[pat]:
            print(f"Error: Unexpected number ({num_found}) of " +
                    f"{pat} transforms found in {name}" +
                    f"\tExpected: {expected_results[pat]} transforms")
            self.expectations_failed = True

def run_datatest(test_case, sample, plugin=True, datatest_path=DATATEST_PATH,
                 plugin_path=PLUGIN_PATH, continue_on_failure=False):
    """
    Run a single data test
    """
    base_command = f"SLEIGHHOME={GHIDRA_INSTALL_DIR}"
    command_detail = f"{datatest_path} < test_data/{sample}.ghidra"
    if plugin:
        command = f"{base_command} DECOMP_PLUGIN={plugin_path} {command_detail}"
    else:
        command = f"{base_command} {command_detail}"
    logger.info(f"Running {command} with output to /tmp/{sample}.testlog")
    if continue_on_failure:
        check_status = False
    else:
        check_status = True
    result = subprocess.run(command, check=check_status, capture_output=True,
                            shell=True, encoding="utf8")
    with open(f"/tmp/{sample}.testlog", "w", encoding="utf8") as f:
        f.write(result.stdout)
        f.write(result.stderr)
    if not continue_on_failure:
        test_case.assertEqual(0, result.returncode,
            f"Datatest of {sample} failed")
        test_case.assertNotIn("Low-level ERROR", result.stdout,
                            "Decompiler completes without a low level error")
        test_case.assertNotIn("Execution error", result.stdout,
                            "Decompiler finds script error")
    trim_output(result.stdout)
    return result

class T0BuildPlugin(unittest.TestCase):
    """
    Build the Ghidra decompiler executables and the sample RISC-V vector plugin
    """

    def test_01_ghidra(self):
        """
        Build and install the Ghidra decompiler and its datatest framework
        """
        logger.info(f"Cleaning the executable directory {DECOMPILER_DIR}")
        for f in (DECOMPILER_PATH, DATATEST_PATH):
            if os.path.exists(f):
                command = f"rm -f {f}"
                logger.info(f"Running {command}")
                result = subprocess.run(command, check=True, capture_output=True,
                                        shell=True, encoding="utf8")
                self.assertEqual(0, result.returncode,
                    "unable to clean previous decompiler executable files")

        # build the decompiler executable used by Ghidra
        command = "bazel build -c opt @ghidra//:decompile"
        logger.info(f"Running {command}")
        result = subprocess.run(command, check=True, capture_output=True,
                                shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "bazel build of the Ghidra decompiler failed")
        result = shutil.copy(BAZEL_BUILD_DECOMPILER_PATH, DECOMPILER_PATH)
        self.assertEqual(result, DECOMPILER_PATH,
                         "Unable to install the decompiler executable")

        # build the decompiler datatest executable
        command = "bazel build -c dbg @ghidra//:decompile_datatest"
        logger.info(f"Running {command}")
        result = subprocess.run(command, check=True, capture_output=True,
                                shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "bazel build of the Ghidra decompiler data_test failed")
        result = shutil.copy(BAZEL_BUILD_DATATEST_PATH, DATATEST_PATH)
        self.assertEqual(result, DATATEST_PATH,
                         "Unable to install the decompiler datatest executable")

    def test_02_plugin(self):
        """
        Build the sample plugin
        """
        logger.info("Removing any previous plugin")
        command = f"rm -f {PLUGIN_PATH}"
        logger.info(f"Running {command}")
        result = subprocess.run(command, check=True, capture_output=True,
                                shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "unable to clean previous decompiler plugin")
        logger.info("Building and installing the plugin")
        command = "bazel build -c dbg plugins:riscv_vector"
        logger.info(f"Running {command}")
        result = subprocess.run(command, check=True, capture_output=True,
                                shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "bazel build of the RISC-V vector transform plugin failed")
        result = shutil.copy(f"bazel-bin/plugins/{PLUGIN_NAME}", "/tmp")
        self.assertEqual(result, PLUGIN_PATH,
                         "Unable to install the decompiler plugin")

class T1Datatests(unittest.TestCase):
    """
    Run any defined datatests
    """
    def setUp(self):
        """
        Accumulate failures here that are only asserted at the end of a unit test
        """
        self.expectations_failed = False

    def test_01_valgrind_exemplars(self):
        """
        Verify correct behavior under valgrind with a small sample of exemplars
        """
        for i in VALGRIND_TEST_SET:
            if i in DEFERRED_TESTS:
                logger.info(f"Deferring test {i} as currently failing")
                continue
            result = run_datatest(self, i, plugin=True, datatest_path=f"valgrind {DATATEST_PATH}")
            assert_expected_transform_count(self, i, result.stdout)
        self.assertFalse(self.expectations_failed,
                         "At least one test reported an unexpected number of transforms")

    def test_02_regular_exemplars(self):
        """
        Verify correct behavior without valgrind, with regular binaries
        """
        for i in REGULAR_TEST_SET:
            if i in DEFERRED_TESTS:
                logger.info(f"Skipping test {i} as currently failing")
                continue
            result =  run_datatest(self, i, plugin=True, datatest_path=f"{DATATEST_PATH}")
            assert_expected_transform_count(self, i, result.stdout)
        self.assertFalse(self.expectations_failed,
                         "At least one test reported an unexpected number of transforms")

    def test_03_failing_exemplars(self):
        """
        Run failing tests to isolate common faults..
        """
        all_tests_successful = True
        for i in DEFERRED_TESTS:
            result = run_datatest(self, i, plugin=True, datatest_path=f"{DATATEST_PATH}",
                                  continue_on_failure=True)
            if result.returncode == 0:
                print(f"The deferred test {i} unexpectedly returned a success error code")
            all_tests_successful &= (result.returncode == 0)
        self.assertTrue(all_tests_successful,
                         "At least one deferred test returned a non-zero exit code")

if __name__ == "__main__":
    unittest.main()
