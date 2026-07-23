#!/usr/bin/python3
"""
Collect and analyze output from a full binary 'export to C' operations
"""

import subprocess
import re
import os
from enum import Enum
from collections import Counter

DATA_DIR = "/tmp"
PLUGIN_LOG = "ghidraPluginManager.log"
LOGGER_ROOT = "ghidraRiscvLogger"
SUMMARIES_ROOT = "riscv_summaries"
OTHER_ROOTS = ("vector_strcmp_summaries", "vector_strlen_summaries")
TRANSFORMS = ("vector_memcpy", "vector_memset", "vector_strlen", "vector_strcmp")
TRANSFORM_PATS = [re.compile(fr"({base})" + r"\(") for base in TRANSFORMS]
transform_counts = {"vector_memcpy":0, "vector_memset":0, "vector_strlen":0, "vector_strcmp":0}

class LogItem():
    """
    variables associated with a line in ghidraRiscvLogger files
    """
    def __init__(self, str_pat : str):
        self.count = 0
        self.text = str_pat
        self.pattern = re.compile(str_pat)

def consolidate(data_dir, file_root, suffix):
    """
    Consolidate per-process files into a single summary file
    """
    command = f"cat {data_dir}/{file_root}_[0-9]*.{suffix} > {data_dir}/{file_root}.{suffix}"
    subprocess.run(command, check=True, capture_output=False,
                            shell=True, encoding="utf8")
C_SUMMARY_TEXT = \
"""
The export C source code shows successful vector transforms.  The `vector_memcpy` and
`vector_memset` transforms can be formed from either vector series or simple vector loops.
The `vector_strlen` and `vector_strcmp` are only found in simple vector loops.
""".strip()

def analyze_c(filename):
    """
    Analyze consolidated reports for a given decompilation
    """
    exception_pat = re.compile(r"Cause: Exception while decompiling ram:")
    low_level_error_pat = re.compile(r"Low-level Error:")
    decompilation_error_pat = re.compile(r"Unable to decompile '(\w+)'")
    vset_pat = re.compile(r"vsetvli|vsetivli")
    print("## Analysis of C/C++ export file\n")
    print("### Scanning " + filename + "\n")
    other_vset_count = 0
    with open(f"{filename}", "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if re.match(exception_pat, line):
                print("* " + line)
            if re.match(decompilation_error_pat, line):
                print("* " + line)
            if re.match(low_level_error_pat, line):
                print("\t\t" + line)
            for i, pat in enumerate(TRANSFORMS):
                match = re.search(pat, line)
                if match:
                    transform_counts[TRANSFORMS[i]] += 1
            match = re.search(vset_pat, line)
            if match:
                other_vset_count += 1
    print("\n### Summary counts\n" + C_SUMMARY_TEXT + "\n")
    print("| count |transform |\n| ---: | :------------ |")
    for i, transform in enumerate(TRANSFORMS):
        print(f"| {transform_counts[transform]} | {transform} |")
    print(f"\n>Note: Also found {other_vset_count} other vsetvli or vsetivli instructions")

WARNINGS_SUMMARY_TEXT = \
"""
This plugin generates warnings when it can no longer continue with a transform attempt.
""".strip()

def analyze_log(filename):
    """
    Analyze the spdlog output to survey for incomplete transforms
    """
    log_line_header_pat = re.compile(r"\[\S+\s\S+\]\s+\[riscv_vector\] \[warning\] (.*)")
    ignore_pat = re.compile(r"^\s+Pcode at")
    log_items = (
        LogItem(r"Unable to complete transform due to reference to loop-local Varnode"),
        LogItem((r"Unable to complete transform due to "
                 r"one or more references to a loop-local Varnode"
                 )),
        LogItem(r"Unable to fully analyze potential complex vector loop stanza"),
        LogItem(r"Failed to extract Vector load pExternal varnode"),
        LogItem(r"Failed to extract Vector store pExternal varnode"),
        LogItem(r"Unrecognized number of vector pcode arguments"),
        LogItem(r"Unrecognized number of scalar pcode arguments"),
        LogItem(r"Vector vset found with no output register"),
        LogItem(r"Failed to collect source register from a vector load operation")
    )
    print(f"\n## Analysis of transform logger file {filename}\n")
    print(WARNINGS_SUMMARY_TEXT)
    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            match = re.search(log_line_header_pat, line)
            if match is None:
                continue
            # remove the log header from our line
            line = match.group(1)
            match = re.search(ignore_pat, line)
            if match:
                continue
            # check key log items to collect frequencies
            warning_recognized = False
            for item in log_items:
                match = re.search(item.pattern, line)
                if match:
                    item.count += 1
                    warning_recognized = True
            if not warning_recognized:
                print(">Warning: Unmatched warning: " + line)
        print("\n### Warning summary counts\n| count | text |\n| ---: | :------------- |")
        log_items = sorted(log_items, key=lambda x: x.count, reverse=True)
        for item in log_items:
            if item.count == 0:
                continue
            print(f"| {item.count} | {item.text} |")

class SummaryRecordTypes(Enum):
    """
    Vector summary records have three types
    """
    VECTOR_SERIES = 0
    VECTOR_LOOP_SIMPLE = 1
    VECTOR_LOOP_COMPLEX = 2
    EMPTY = 3

simple_signatures = Counter()
complex_signatures = Counter()
unhandled_instructions = Counter()
VECTOR_INSTRUCTION_HEADER_REGEX = (r"^Vector instructions "
                                   r"\(handled \| unhandled \| epilog\):\s+(.*)"
                                   )
vector_instruction_header_pat = re.compile(VECTOR_INSTRUCTION_HEADER_REGEX)
VECTOR_INSTRUCTION_ITEM_PAT = r"[a-zA-Z0-9,_ ]+"
# get the instructions handled as group(1) and any extension as group(2)
SIGNATURE_REGEX = fr"({VECTOR_INSTRUCTION_ITEM_PAT}),\s\|(.*)\|(.*)"
signature_pat = re.compile(SIGNATURE_REGEX)

def analyze_simple_loop(buffer):
    """
    Analyze the summary record of a simple loop
    """
    for line in buffer:
        line = line.strip()
        match = re.search(vector_instruction_header_pat, line)
        if not match:
            continue
        instructions = match.group(1)
        match = re.search(signature_pat, instructions)
        if match:
            handled = match.group(1)
            simple_signatures[handled] += 1
            other_fields = match.group(2).split("|")
            unhandled = other_fields[0]
            for inst in unhandled.split():
                instruction_name = inst[:-1]
                unhandled_instructions[instruction_name] += 1

def analyze_complex_loop(buffer):
    """
    Analyze the summary record of a complex loop
    """
    for line in buffer:
        line = line.strip()
        match = re.search(vector_instruction_header_pat, line)
        if not match:
            continue
        instructions = match.group(1)
        match = re.search(signature_pat, instructions)
        if match:
            handled = match.group(1)
            complex_signatures[handled] += 1
            other_fields = match.group(2).split("|")
            unhandled = other_fields[0]
            for inst in unhandled.split():
                instruction_name = inst[:-1]
                unhandled_instructions[instruction_name] += 1

def analyze_series():
    """
    Analyze the summary record of a simple series
    """

COUNTS_TO_SHOW = 50

record_stats = Counter()

SIMPLE_LOOP_TEXT = \
"""
Simple loops consist of a single Ghidra block with no internal jumps or calls other than
the conditional branch returning to the start of the block.  Builtins like `memcpy` and
`strcmp` generally result in simple loops.
""".strip()
COMPLEX_LOOP_TEXT = \
"""
Complex loops consist of multiple Ghidra blocks with at least one internal jump or call other than
the conditional branch returning to the start of the block.  Builtins like `strncmp`
generally result in complex loops.
""".strip()

UNHANDLED_INSTR_TEXT = \
"""
Handled vector instructions each have a lambda expression providing for their basic semantics.
Unhandled instructions have no such lambda defined, and can not be used in a transform match.
""".strip()

def generate_summaries_results(simple_sigs, complex_sigs, unhandled):
    """
    Report summaries file analysis results in Markdown format
    """

    print("\n**Simple loop signatures**\n")
    print(SIMPLE_LOOP_TEXT)
    print((
        "\nRecognized (aka 'handled') vector instruction sequences "
        "are found in simple loop bodies:"))
    print(f"The most common {COUNTS_TO_SHOW} are:\n")
    print("| count | handled instructions |")
    print("| ---: | :-------- |")
    for item, count in simple_sigs.most_common(COUNTS_TO_SHOW):
        print(f"| {count} | {item} |")
    print("\n**Complex loop signatures**\n")
    print(COMPLEX_LOOP_TEXT)
    print((
            "\nRecognized (aka 'handled') vector instruction sequences "
             " are found in complex loop bodies:")
    )
    print(f"\nThe most common {COUNTS_TO_SHOW} are:\n")
    print("| count | handled instructions |")
    print("| -: | :-------- |")
    for item, count in complex_sigs.most_common(COUNTS_TO_SHOW):
        print(f"| {count} | {item} |")
    print("\n**Unhandled loop instructions**\n")
    print(UNHANDLED_INSTR_TEXT)
    print(f"\nThe most common {COUNTS_TO_SHOW} are:\n")
    print("| count | unhandled instructions |")
    print("| -: | :-------- |")
    for item, count in unhandled.most_common(COUNTS_TO_SHOW):
        print(f"| {count} | {item} |")

def analyze_summaries(filename):
    """
    Select key data from the loop and series summary report
    """
    vector_series_regex = r"Vector Series:"
    vector_loop_simple_regex = r"Vector Loop \(simple\):"
    vector_loop_complex_regex = r"Vector Loop \(complex\):"
    vector_series_pat = re.compile(vector_series_regex)
    vector_loop_simple_pat = re.compile(vector_loop_simple_regex)
    vector_loop_complex_pat = re.compile(vector_loop_complex_regex)

    print("\n## Analysis of loop and series summary file\n")

    with open(filename, "r", encoding="utf-8") as file:
        buffer = []
        this_buffer = SummaryRecordTypes.EMPTY
        file_size = os.path.getsize(filename)
        while True:
            line = file.readline().strip()
            if not line:
                break
            eof = file.tell() == file_size
            match_series = re.search(vector_series_pat, line)
            match_simple = re.search(vector_loop_simple_pat, line)
            match_complex = re.search(vector_loop_complex_pat, line)
            match_found = (match_simple is not None) or \
                (match_complex is not None) or \
                (match_series is not None)
            if match_found or eof:
                if len(buffer) > 0:
                    # process prior record appropriately
                    if this_buffer == SummaryRecordTypes.VECTOR_LOOP_SIMPLE:
                        analyze_simple_loop(buffer)
                        record_stats['VECTOR_LOOP_SIMPLE_ANALYZED'] += 1
                    if this_buffer == SummaryRecordTypes.VECTOR_LOOP_COMPLEX:
                        analyze_complex_loop(buffer)
                        record_stats['VECTOR_LOOP_COMPLEX_ANALYZED'] += 1
                    if this_buffer == SummaryRecordTypes.VECTOR_SERIES:
                        record_stats['VECTOR_SERIES_ANALYZED'] += 1
                    buffer = []
                if match_series:
                    this_buffer = SummaryRecordTypes.VECTOR_SERIES
                    record_stats['VECTOR_SERIES'] += 1
                if match_simple:
                    this_buffer = SummaryRecordTypes.VECTOR_LOOP_SIMPLE
                    record_stats['VECTOR_LOOP_SIMPLE'] += 1
                if match_complex:
                    this_buffer = SummaryRecordTypes.VECTOR_LOOP_COMPLEX
                    record_stats['VECTOR_LOOP_COMPLEX'] += 1
                continue
            buffer.append(line)
    generate_summaries_results(simple_signatures, complex_signatures, unhandled_instructions)

def analyze_surveys():
    """
    Select key data from registered transform-specific survey reports
    """
