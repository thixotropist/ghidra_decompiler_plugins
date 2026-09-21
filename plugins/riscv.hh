/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef RISCV_HH_
#define RISCV_HH_

#include <string>
#include <map>
#include <climits>
#include <fstream>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/type.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/address.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/space.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"

#include "framework.hh"

/**
 * @file riscv.hh
 * @brief Components available to RISCV-64 plugins
 */
namespace ghidra
{
/// @brief Rule application return value if no changes performed
static const int RETURN_NO_TRANSFORM = 0;
/// @brief Rule application return value if changes were performed
static const int RETURN_TRANSFORM_PERFORMED = 1;
extern Architecture* arch;
extern AddrSpace* registerAddrSpace;
extern AddrSpace* uniqueAddrSpace;
extern AddrSpace* ramAddrSpace;
extern AddrSpace* stackAddrSpace;

// utility functions
extern std::shared_ptr<ghidra::Inspector> inspector;
}

namespace riscv_vector
{
static const int TRANSFORM_LIMIT_LOOPS = INT_MAX; ///<@brief maximum number of loop transforms to attempt
static const int TRANSFORM_LIMIT_NONLOOPS = INT_MAX; ///<@brief maximum number of loop transforms to attempt
//static const int TRANSFORM_LIMIT_NONLOOPS = 0; ///<@brief maximum number of loop transforms to attempt
//static const int TRANSFORM_LIMIT_LOOPS = 9; ///<@brief maximum number of loop transforms to attempt
static const bool SURVEY_ACTION_DATABASE = false; ///<@brief report on Actions available and triggered

extern int transformCountNonLoop;
extern int transformCountLoop;
static const ghidra::uint4 RISCV_VEC_INSN_8_BIT_ELEM  = 0x00000001;   ///< 8 bit element override
static const ghidra::uint4 RISCV_VEC_INSN_16_BIT_ELEM = 0x00000002;   ///< 16 bit element override
static const ghidra::uint4 RISCV_VEC_INSN_32_BIT_ELEM = 0x00000004;   ///< 32 bit element override
static const ghidra::uint4 RISCV_VEC_INSN_64_BIT_ELEM = 0x00000008;   ///< 64 bit element override
static const ghidra::uint4 RISCV_VEC_INSN_FAULT_ONLY_FIRST = 0x00000010;  ///< fault-only-first load semantics
static const ghidra::uint4 RISCV_VEC_INSN_MASK_SET = 0x00000020;      ///< conditional mask set

// Begin identifiers for *typed* user pcode builtins
static const ghidra::uint4 VECTOR_MEMSET = 0x11000000;      ///< Ghidra ID for typed vector_memset
static const ghidra::uint4 VECTOR_MEMCPY = 0x11000001;      ///< Ghidra ID for typed vector_memcpy
static const ghidra::uint4 VECTOR_STRLEN = 0x11000002;      ///< Ghidra ID for typed vector_strlen
static const ghidra::uint4 VECTOR_STRCMPNEQ = 0x11000003;   ///< Ghidra ID for typed vector_strcmpneq
static const ghidra::uint4 VECTOR_STRCMP = 0x11000004;      ///< Ghidra ID for typed vector_strcmp
static const ghidra::uint4 VECTOR_STRNCMPNEQ = 0x11000005;  ///< Ghidra ID for typed vector_strncmpneq
static const ghidra::uint4 VECTOR_STRNCMP = 0x11000006;     ///< Ghidra ID for typed vector_strncmp

/// @brief A file holding summary data for each possible vector stanza
extern std::ofstream reportFile;

// Define epilog survey report infrastructure

/// @brief True if we need to collect epilog sequences from potential vector_strlen sequences
static const bool COLLECT_STRLEN_SAMPLES = true;
/// @brief File stream for vector_strlen sequence collections
extern std::ofstream strlenSampleFile;
/// @brief True if we need to collect epilog sequences from potential vector_strcmp sequences
static const bool COLLECT_STRCMP_SAMPLES = true;
/// @brief File stream for vector_strcmp sequence collections
extern std::ofstream strcmpSampleFile;

}
#endif /* RISCV_HH_ */
