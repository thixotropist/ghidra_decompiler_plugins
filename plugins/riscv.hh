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
#include "framework.hh"

/**
 * @file riscv.hh
 * @brief Components available to RISCV-64 plugins
 */


namespace ghidra
{
static const int RETURN_NO_TRANSFORM = 0;
static const int RETURN_TRANSFORM_PERFORMED = 1;
extern Architecture* arch;
extern AddrSpace* registerAddrSpace;
}

namespace riscv_vector
{
static const int TRANSFORM_LIMIT_LOOPS = INT_MAX; ///<@brief maximum number of loop transforms to attempt
static const int TRANSFORM_LIMIT_NONLOOPS = INT_MAX; ///<@brief maximum number of loop transforms to attempt
//static const int TRANSFORM_LIMIT_NONLOOPS = 0; ///<@brief maximum number of loop transforms to attempt
//static const int TRANSFORM_LIMIT_LOOPS = 9; ///<@brief maximum number of loop transforms to attempt

extern int transformCountNonLoop;
extern int transformCountLoop;
static const ghidra::uint4 RISCV_VEC_INSN_8_BIT_ELEM  = 0x00000001;   ///< 8 bit element override
static const ghidra::uint4 RISCV_VEC_INSN_16_BIT_ELEM = 0x00000002;   ///< 16 bit element override
static const ghidra::uint4 RISCV_VEC_INSN_32_BIT_ELEM = 0x00000004;   ///< 32 bit element override
static const ghidra::uint4 RISCV_VEC_INSN_64_BIT_ELEM = 0x00000008;   ///< 64 bit element override
static const ghidra::uint4 RISCV_VEC_INSN_FAULT_ONLY_FIRST = 0x00000010;  ///< fault-only-first load semantics
static const ghidra::uint4 RISCV_VEC_INSN_MASK_SET = 0x00000020;      ///< conditional mask set

// Begin identifiers for *typed* user pcode builtins
static const ghidra::uint4 VECTOR_MEMSET = 0x11000000;
static const ghidra::uint4 VECTOR_MEMCPY = 0x11000001;
static const ghidra::uint4 VECTOR_STRLEN = 0x11000002;

extern std::ofstream reportFile;

/**
 * @brief Group RISC-V user pcodes according to their generic roles
 * in common vector sequences
 */
class RiscvUserPcode {
    public:
        const std::string& asmOpcode;    ///<@brief the name of this opcode as it appears in SLEIGH semantics
        int ghidraOp;                    ///<@brief the index by which Ghidra identifies this User Pcode
        int elementSize;                 ///<@brief number of bytes per vector element
        int multiplier;                  ///<@brief vset multiplier if >= 1
        uint flags;                      ///<@brief RISCV_VEC_INSN flags found within a loop
        bool isVset;                     ///<@brief true if this is a vsetvli* instruction
        bool isVseti;                    ///<@brief true if this is a vsetivli* instruction
        bool isLoad;                     ///<@brief true if this is a simple vector load from memory
        bool isFaultOnlyFirst;           ///<@brief true if this is a load with fault-only-first semantics
        bool isStore;                    ///<@brief true if this is a simple vector store
        bool isLoadImmediate;            ///<@brief true if this is a simple vector load immediate
        bool isVectorOp;                 ///<@brief true if this op depends on a prior vset* instruction
        bool isMaskSet;                  ///<@brief true if this is a conditional mask set vector op
        /**
         * @brief Construct a new Riscv User Pcode object
         *
         * @param op the name of this opcode as it appears in SLEIGH semantics
         * @param index the index by which Ghidra identifies this User Pcode
         */
        RiscvUserPcode(const std::string& op, int index);
        /**
         * @brief Get the User Pcode object from a Ghidra PcodeOp
         *
         * @param op
         * @return a RiscvUserPcode* describing the UserPcodeOp
         */
        static const RiscvUserPcode* getUserPcode(const ghidra::PcodeOp& op);
};
/**
 * @brief Map providing RiscvUserPcode information given the ghidra identifier as a key
 */
extern std::map<int, RiscvUserPcode*> riscvPcodeMap;
/**
 * @brief Map providing the ghidra identifier for a given Risc-v opcode name
 */
extern std::map<std::string, ghidra::uintb> riscvNameToGhidraId;

}
#endif /* RISCV_HH_ */
