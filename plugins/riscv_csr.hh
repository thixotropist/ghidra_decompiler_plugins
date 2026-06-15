#ifndef RISCV_CSR_HH
#define RISCV_CSR_HH

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"

#include "framework.hh"
/**
 * @file riscv_csr.hh
 * @brief Provide pre- and post-transform processing steps to bring Control and Status Register
 * PcodeOps into a more sensible structure.
 * @details The RISC-V control and status registers don't fit into the same heritage calculations
 * as do regular registers.  This Rule edits a function's PCode to make appropriate adjustments.
 *
 * These control and status registers are currently present in the dpdk-l3fwd exemplar and handled here:
 * - vlenb - the current hart's vector register length, in bytes.  This should be treated as a constant
 *   value. CSR 0xc22.
 * - vl - the current vector length, as set by vset* instructions and optionally reduced by vector load
 *   fail-first instructions.  This should never collect heritage or MULTIEQUAL opcodes.  CSR 0xc20.
 * - time - a time counter with unspecified units of measurement, for instance ticks or ns.  CSR 0xc01.
 *   This should never collect heritage or MULTIEQUAL opcodes.
 *
 * Common patterns to be processed include
 *
 * - ... = - c0x0c22(i)
 * - ... = c0x0c22(i) + u0x10000075(0x00100024:67a)
 * - ... = c0x0c22(i) ? c0x0c22(i) ? c0x0c22(i) ? c0x0c22(i) ? c0x0c22(i)
 * - ... = a3(0x00100000:1) ? c0x0c20(i)
 * - ... = c0x0c20(0x00100024:19) = c0x0c20(i)
 * - ... = c0x0c20(0x0010002c:27) = c0x0c20(i) [] i0x0010002c:6(free)
 * - ... = a2(0x001000d2:11) = a2(0x001000b0:33) - c0x0c20(i)
 * - ... = c0x0c22(free) ? c0x0c22(free) ? c0x0c22(0x000c4230:3301) ? c0x0c22(free)
 * - ... = c0x0c22(free) [] i0x000c3138:28e(free)
 *
 * @todo This code should probably be turned into Action plugin code, inserted before and after the `oppool1`
 * Action.
 */

namespace riscv_vector
{

/**
 * @brief Actions to perform on the entire Function before running rules in the oppool1 pool
 * @warning The register offsets here aonly work for RISC-V 64 bit processors.
 */
class ActionPluginPrepare
{
  public:
    ///@brief The CSR wordsize, probably the same as the scalar register size
    /// @todo Fetch this value from the Architecture object if we want rv32 capability
    static const uint32_t CSR_WORDSIZE = 8;
    /// @brief The RISC-V register address for `TIME`
    static const uint32_t TIME_ADDR = 0xc01;
    /// @brief The RISC-V register address for `VL`
    static const uint32_t VL_ADDR = 0xc20;
    /// @brief The RISC-V register address for `VLENB`
    static const uint32_t VLENB_ADDR = 0xc22;

    /// @brief The offset in csreg space given to the "time" register
    static const ghidra::uintb timeRegisterOffset = TIME_ADDR * CSR_WORDSIZE;
    /// @brief The offset in csreg space given to the "vl" register
    static const ghidra::uintb vlRegisterOffset = VL_ADDR * CSR_WORDSIZE;
    /// @brief The offset in csreg space given to the "vlenb" register
    static const ghidra::uintb vlenbRegisterOffset = VLENB_ADDR * CSR_WORDSIZE;

    /**
     * @brief Construct a new Action Plugin Prepare object
     * @param thisData Function context to use
     * @param myLogger Logger to use
     */
    explicit ActionPluginPrepare(ghidra::Funcdata& thisData, std::shared_ptr<spdlog::logger> myLogger);
    /**
     * @brief allow for static initialization once per plugin instance
     */
    static void static_init();
    /**
     * @brief Examine all accesses of RISC-V Control and Status Registers to better manage heritage
     * and stack processes.
     */
    void adjustCsrProcessing();
  private:
    /// @brief  The Function context data to use within this class
    ghidra::Funcdata& data;
    /// @brief the logger to use within this class
    std::shared_ptr<spdlog::logger> logger;
    /// @brief map of constant CSRs to their replacement values
    static std::map<uint32_t, uint32_t> replacement_values;
    /// @brief A constant Varnode to use in place of `VLENB` varnodes.
    static ghidra::Varnode* vlenb_constant_vn;
};
}

#endif /* RISCV_CSR_HH */
