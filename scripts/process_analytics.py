#!/usr/bin/python3
"""
Collect and analyze output from a full binary 'export to C' operations
"""

import argparse

import analytics

DATA_DIR = "/tmp"
LOGGER_ROOT = "ghidraRiscvLogger"
SUMMARIES_ROOT = "riscv_summaries"
OTHER_ROOTS = ("vector_strcmp_summaries", "vector_strlen_summaries")

EPILOG = """
The analysis is output as a Markdown file.  If you prefer html,
pipe it through 'pandoc -t html -s -V maxwidth=100% -o log.html'
"""
parser = argparse.ArgumentParser(description="Ghidra decompiler analytics",
                                 epilog = EPILOG)
parser.add_argument("input_root", type=str, help="Name of exported binary")
parser.add_argument("mode", choices=["full", "consolidate", "analyze"], default="consolidate",
                    help="whether to do a full or partial/incremental analysis")
args = parser.parse_args()
DO_CONSOLIDATION = args.mode in ("full", "consolidate")
DO_ANALYSIS = args.mode in ("full", "analyze")
C_FILENAME = f"{DATA_DIR}/{args.input_root}.c"
print(f"# Analysis of {args.input_root} RISC-V Transform results\n")
if DO_CONSOLIDATION:
    analytics.consolidate(DATA_DIR, LOGGER_ROOT, "log")
    analytics.consolidate(DATA_DIR, SUMMARIES_ROOT, "txt")
    for root in OTHER_ROOTS:
        analytics.consolidate(DATA_DIR, root, "txt")
if DO_ANALYSIS:
    analytics.analyze_c(C_FILENAME)
    analytics.analyze_log(f"{DATA_DIR}/{LOGGER_ROOT}.log")
    analytics.analyze_summaries(f"{DATA_DIR}/{SUMMARIES_ROOT}.txt")
    analytics.analyze_surveys()
