#!/usr/bin/python3
"""
Test analytics module
"""
from pathlib import Path
import unittest
import re

import analytics

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = f"{SCRIPT_DIR}/test_data"
LOGGER_ROOT = "ghidraRiscvLogger"
SUMMARIES_ROOT = "riscv_summaries"
OTHER_ROOTS = ("vector_strcmp_summaries", "vector_strlen_summaries")

class T0Consolidate(unittest.TestCase):
    """
    Verify that we can consolidate data from two processes
    """
    def test_01_logger(self):
        """
        The logger files are the first to consolidate
        """
        analytics.consolidate(DATA_DIR, LOGGER_ROOT, "log")
        consolidated_file_size = Path(f"{DATA_DIR}/{LOGGER_ROOT}.log").stat().st_size
        self.assertEqual(consolidated_file_size, 265689,
                         "Consolidating the logger output files failed")

    def test_02_summaries(self):
        """
        The summaries files are the second to consolidate
        """
        analytics.consolidate(DATA_DIR, SUMMARIES_ROOT, "txt")
        consolidated_file_size = Path(f"{DATA_DIR}/{SUMMARIES_ROOT}.txt").stat().st_size
        self.assertEqual(consolidated_file_size, 1176390,
                         "Consolidating the vector summaries output files failed")

class T1Analyze(unittest.TestCase):
    """
    Perform analyses on a subset of the consolidated data
    """
    def test_01_c(self):
        """
        scan a subset of a large C export for decompiler warnings
        """
        analytics.analyze_c(f"{DATA_DIR}/decompiled_source.c")

    def test_02_logger(self):
        """
        The logger files show warnings to collect
        """
        analytics.analyze_log(f"{DATA_DIR}/{LOGGER_ROOT}.log")

    def test_03_summaries_regexs(self):
        """
        Test key regexes used in summary analses
        """
        simple_sample = (
            "Vector instructions (handled | unhandled | epilog): vsetvli_e8m1tama, vle8ff_v, "
            "vmsne_vv, vmseq_vi, vmor_mm, vfirst_m, | | +, +, ?, "
        )
        complex_sample = (
            "Vector instructions (handled | unhandled | epilog): vse64_v, "
            "vse32_v, | vsetivli_e64m1tama, vid_v, vmul_vx, vsetvli_e32mf2tama, "
            "vmv_v_i, vsetvli_e64m1tama, vadd_vx, | ?,"
        )
        match1 = re.search(analytics.vector_instruction_header_pat, simple_sample)
        self.assertIsNotNone(match1,
                             "Failed to identify simple sample's vector instruction header")
        report = match1.group(1)
        match1a = re.search(analytics.SIGNATURE_REGEX, report)
        self.assertIsNotNone(match1a,
                             "Failed to match components of the signature report")
        self.assertEqual(match1a.group(1),
                         "vsetvli_e8m1tama, vle8ff_v, vmsne_vv, vmseq_vi, vmor_mm, vfirst_m",
                         "Failed to located handled instructions")
        print(f"Match.group(2) = {match1a.group(2)}")
        print(f"Match.group(3) = {match1a.group(3)}")

        match2 = re.search(analytics.vector_instruction_header_pat, complex_sample)
        self.assertIsNotNone(match2,
                             "Failed to identify complex sample's vector instruction header")
        report = match2.group(1)
        match2a = re.search(analytics.SIGNATURE_REGEX, report)
        self.assertIsNotNone(match2a,
                             "Failed to match components of the signature report")
        self.assertEqual(match2a.group(1), "vse64_v, vse32_v",
                         "Failed to located handled instructions")
        print(f"Match.group(2) = {match2a.group(2)}")
        print(f"Match.group(3) = {match2a.group(3)}")


    def test_04_summaries(self):
        """
        The summaries files describe vector series and loops
        """
        analytics.analyze_summaries(f"{DATA_DIR}/{SUMMARIES_ROOT}.txt")
        self.assertEqual(analytics.record_stats['VECTOR_LOOP_SIMPLE'], 1033,
                         "Failed to find the expected number of simple loops")
        self.assertEqual(analytics.record_stats['VECTOR_LOOP_SIMPLE_ANALYZED'], 1033,
                         "Failed to find the expected number of simple loop analyses")
        self.assertEqual(analytics.record_stats['VECTOR_LOOP_COMPLEX'], 147,
                         "Failed to find the expected number of complex loops")
        self.assertEqual(analytics.record_stats['VECTOR_LOOP_COMPLEX_ANALYZED'], 147,
                         "Failed to find the expected number of complex loop analyses")

if __name__ == "__main__":
    unittest.main()
