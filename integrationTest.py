#!/usr/bin/python3
"""
Verify the correctness of the RISC-V Vector transforms Ghidra plugin
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

expected = {
    'memcpy_exemplars': {'vector_memset':0, 'vector_memcpy':5, 'vector_strlen':0},
    'whisper_sample_1': {'vector_memset':0, 'vector_memcpy':1, 'vector_strlen':1},
    'whisper_main': {'vector_memset':4, 'vector_memcpy':13, 'vector_strlen':1},
    'whisper_sample_2': {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'whisper_sample_3':  {'vector_memset':0, 'vector_memcpy':5, 'vector_strlen':0},
    'whisper_sample_4':  {'vector_memset':16, 'vector_memcpy':86, 'vector_strlen':0},
    'whisper_sample_5':  {'vector_memset':3, 'vector_memcpy':20, 'vector_strlen':1},
    'whisper_sample_6':  {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'whisper_sample_7':  {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'whisper_sample_8':  {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'whisper_sample_10':  {'vector_memset':0, 'vector_memcpy':3, 'vector_strlen':0},
    'dpdk_sample_1':  {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':0},
    'dpdk_sample_2':  {'vector_memset':0, 'vector_memcpy':1, 'vector_strlen':0},
    'dpdk_sample_3':  {'vector_memset':0, 'vector_memcpy':0, 'vector_strlen':2},
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
    while (True):
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

def assert_expected_transform_count(test_case, name, result_output):
    """
    count the number of vector transforms in the C section of a testcase stdout
    :param testCase: the invoked unit test case
    :param name: the name identifying the expected results
    :param result_output: the process output from the decompilation
    """
    source = extract_c(result_output.stdout)
    expected_results = expected[name]
    for pat in ('vector_memset', 'vector_memcpy', 'vector_strlen'):
        num_found = source.count(pat)
        print(f"found {num_found} instances of {pat} in test case {name}")
        test_case.assertEqual(num_found, expected_results[pat],
                            f"Unexpected number ({num_found}) of {pat} transforms found in {name}")

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
    def test_01_memcpy_exemplars(self):
        """
        Verify correct behavior with minimal memcpy binaries
        """
        command = f"SLEIGHHOME={GHIDRA_INSTALL_DIR} DECOMP_PLUGIN={PLUGIN_PATH} valgrind {DATATEST_PATH} < test/memcpy_exemplars.ghidra"
        logger.info(f"Running {command}")
        result = subprocess.run(command, check=True, capture_output=True,
                                shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "Datatest of memcpy_exemplars failed")
        with open("/tmp/memcpy_exemplars.testlog", "w", encoding="utf8") as f:
            f.write(result.stdout)
            f.write(result.stderr)
        trim_output(result.stdout)
        assert_expected_transform_count(self, 'memcpy_exemplars', result)
        self.assertIn("successfully loaded: RISC-V 64", result.stdout,
                         "Failed to load test/memcpy_exemplars_save.xml")
        self.assertIn("vector_memcpy((void *)to,(void *)from,2);", result.stdout,
                      "Failed to find a vector memcpy of 2 bytes")
        self.assertIn("vector_memcpy((void *)to,(void *)from,4);", result.stdout,
                      "Failed to find a vector memcpy of 4 bytes")
        self.assertIn("vector_memcpy((void *)to,(void *)from,8);", result.stdout,
                      "Failed to find a vector memcpy of 8 bytes")
        self.assertIn("vector_memcpy((void *)to,(void *)from,0xf);", result.stdout,
                      "Failed to find a vector memcpy of 15 bytes")
        self.assertIn("vector_memcpy((void *)to,(void *)from,size);", result.stdout,
                      "Failed to find a vector memcpy loop of arbitrary size")
        self.assertIn("definitely lost: 0 bytes in 0 blocks", result.stderr,
                      "Memory Leak or invalid read access detected")

    def test_02_whisper_selection_main_function(self):
        """
        Verify correct behavior with the main function of whisper-cpp
        Note: this test skips valgrind analysis in favor of speed
        """
        command = f"SLEIGHHOME={GHIDRA_INSTALL_DIR} DECOMP_PLUGIN={PLUGIN_PATH} {DATATEST_PATH} < test/whisper_main.ghidra"
        logger.info(f"Running {command} with output to /tmp/whisper_main.testlog")
        result = subprocess.run(command, check=True, capture_output=True,
                                shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "Datatest of whisper_main failed")
        with open("/tmp/whisper_main.testlog", "w", encoding="utf8") as f:
            f.write(result.stdout)
            f.write(result.stderr)
        trim_output(result.stdout)
        assert_expected_transform_count(self, 'whisper_main', result)

    def test_03_exemplar_regression(self):
        """
        Verify processing of several Whisper and dpdk functions
        """
        sample_set = []
        for i in (1,2,3,4,5,6,7,8,10):
            sample_set.append(f"whisper_sample_{i}")
        for i in (1,2,3):
            sample_set.append(f"dpdk_sample_{i}")
        for sample in sample_set:
            command = f"SLEIGHHOME={GHIDRA_INSTALL_DIR} DECOMP_PLUGIN={PLUGIN_PATH} {DATATEST_PATH} < test/{sample}.ghidra"
            logger.info(f"Running {command} with output to /tmp/{sample}.testlog")
            result = subprocess.run(command, check=True, capture_output=True,
                                    shell=True, encoding="utf8")
            self.assertEqual(0, result.returncode,
                f"Datatest of {sample} failed")
            with open(f"/tmp/{sample}.testlog", "w", encoding="utf8") as f:
                f.write(result.stdout)
                f.write(result.stderr)
            self.assertNotIn("Low-level ERROR", result.stdout,
                             "Decompiler completes without a low level error")
            trim_output(result.stdout)
            assert_expected_transform_count(self, f"{sample}", result)

if __name__ == "__main__":
    unittest.main()
