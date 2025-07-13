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

GHIDRA_INSTALL_DIR = "/opt/ghidra_12.0_DEV/"
DECOMPILER_DIR = GHIDRA_INSTALL_DIR + "Ghidra/Features/Decompiler/os/linux_x86_64/"
DECOMPILER_PATH = DECOMPILER_DIR + "decompile"
DATATEST_PATH = DECOMPILER_DIR + "decompile_datatest"
BAZEL_BUILD_DECOMPILER_PATH = "bazel-bin/external/+_repo_rules+ghidra/decompile"
BAZEL_BUILD_DATATEST_PATH = "bazel-bin/external/+_repo_rules+ghidra/decompile_datatest"
PLUGIN_LOAD_DIR = "/tmp/"
PLUGIN_NAME = "libriscv_vector.so"
PLUGIN_PATH = PLUGIN_LOAD_DIR + PLUGIN_NAME

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
                result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
                self.assertEqual(0, result.returncode,
                    "unable to clean previous decompiler executable files")

        # build the decompiler executable used by Ghidra
        command = "bazel build -c opt @ghidra//:decompile"
        logger.info(f"Running {command}")
        result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "bazel build of the Ghidra decompiler failed")
        result = shutil.copy(BAZEL_BUILD_DECOMPILER_PATH, DECOMPILER_PATH)
        self.assertEqual(result, DECOMPILER_PATH,
                         "Unable to install the decompiler executable")

        # build the decompiler datatest executable
        command = "bazel build -c dbg @ghidra//:decompile_datatest"
        logger.info(f"Running {command}")
        result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
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
        result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "unable to clean previous decompiler plugin")
        logger.info("Building and installing the plugin")
        command = "bazel build -c dbg plugins:riscv_vector"
        logger.info(f"Running {command}")
        result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
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
        result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "Datatest of memcpy_exemplars failed")
        with open("/tmp/memcpy_exemplars.testlog", "w", encoding="utf8") as f:
            f.write(result.stdout)
            f.write(result.stderr)
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

    def test_02_whisper_selection_simple(self):
        """
        Verify correct behavior with more complex functions extracted from whisper-cpp
        """
        command = f"SLEIGHHOME={GHIDRA_INSTALL_DIR} DECOMP_PLUGIN={PLUGIN_PATH} valgrind {DATATEST_PATH} < test/whisper_sample_1.ghidra"
        logger.info(f"Running {command} with output to /tmp/whisper_sample_1.testlog")
        result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "Datatest of whisper_sample_1 failed")
        with open("/tmp/whisper_sample_1.testlog", "w", encoding="utf8") as f:
            f.write(result.stdout)
            f.write(result.stderr)
        self.assertIn("vector_memcpy((void *)lVar1,(void *)param1,(ulong)pcVar4)", result.stdout,
                      "Vector_memcpy transform was not as expected")
        self.assertIn("definitely lost: 0 bytes in 0 blocks", result.stderr,
                      "Memory Leak or invalid read access detected")

    def test_02_whisper_selection_main_function(self):
        """
        Verify correct behavior with the main function of whisper-cpp
        Note: this test skips valgrind analysis in favor of speed
        """
        command = f"SLEIGHHOME={GHIDRA_INSTALL_DIR} DECOMP_PLUGIN={PLUGIN_PATH} {DATATEST_PATH} < test/whisper_main.ghidra"
        logger.info(f"Running {command} with output to /tmp/whisper_main.testlog")
        result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
        self.assertEqual(0, result.returncode,
            "Datatest of whisper_main failed")
        with open("/tmp/whisper_main.testlog", "w", encoding="utf8") as f:
            f.write(result.stdout)
            f.write(result.stderr)
        self.assertIn("vector_memset((void *)auStack_650,0,0x10)", result.stdout,
                      "Vector_memset transform was not as expected")
        self.assertIn("vector_memcpy((void *)&uStack_274,(void *)0x107f20,0x10)", result.stdout,
                      "Vector_memcpy fixed length transform was not as expected")

    def test_03_whisper_regression(self):
        """
        Verify processing of several Whisper functions that previously threw exceptions
        """
        sample_set = (2,3,5,6,7)
        for i in sample_set:
            command = f"SLEIGHHOME={GHIDRA_INSTALL_DIR} DECOMP_PLUGIN={PLUGIN_PATH} {DATATEST_PATH} < test/whisper_sample_{i}.ghidra"
            logger.info(f"Running {command} with output to /tmp/whisper_sample_{i}.testlog")
            result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
            self.assertEqual(0, result.returncode,
                f"Datatest of whisper_sample_{i} failed")
            with open(f"/tmp/whisper_sample_{i}.testlog", "w", encoding="utf8") as f:
                f.write(result.stdout)
                f.write(result.stderr)
            self.assertNotIn("Low-level ERROR", result.stdout, 
                             "Decompiler completes without a low level error")
            command = f"grep -P '^\\s+vector_(?:memcpy|memset|strlen)' /tmp/whisper_sample_{i}.testlog|wc|awk '{{print $1}}'"
            result = subprocess.run(command, check=True, capture_output=True, shell=True, encoding="utf8")
            self.assertEqual(0, result.returncode,
                f"Transform count collection for whisper_sample_{i} failed")
            logger.info(f"Found {result.stdout.strip()} vector transforms in whisper_sample_{i}")

    @unittest.skip("Throws decompiler exception")
    def test_04_whisper_failures(self):
        """
        This currently throws a std::vector assertion error even with no plugin
        within ghidra::Heritage::splitByRefinement at heritage.cc:1748
        """
        test_name = "whisper_sample_4"
        enable_plugin = False
        enable_valgrind = False
        if enable_plugin:
            plugin = f"DECOMP_PLUGIN={PLUGIN_PATH}"
        else:
            plugin = ""
        if enable_valgrind:
            valgrind = "valgrind"
        else:
            valgrind = ""
        command = f"SLEIGHHOME={GHIDRA_INSTALL_DIR} {plugin} {valgrind} {DATATEST_PATH} < test/{test_name}.ghidra"
        logger.info(f"Running {command} with output to /tmp/{test_name}.testlog")
        result = subprocess.run(command, check=False, capture_output=True, shell=True, encoding="utf8")
        with open(f"/tmp/{test_name}.testlog", "w", encoding="utf8") as f:
            f.write(result.stdout)
            f.write(result.stderr)
        self.assertEqual(0, result.returncode,
            f"Datatest of {test_name} failed")

if __name__ == "__main__":

    unittest.main()
