#ifndef RISCV_CSR_HH
#define RISCV_CSR_HH
#include "spdlog/spdlog.h"
#include "framework.hh"
/**
 * @file riscv_csr.hh
 * @brief Provide pre- and post-transform processing steps to bring Control and Status Register
 * PcodeOps into a more sensible structure.
 * @details The initial purpose of this code is to remove the `vl` vector length register from Heritage
 * calculations.  With these changes the Decompiler should no longer attempt to track the state of this
 * register.
 *
 * @todo This code should probably be turned into Action plugin code, inserted before and after the `oppool1`
 * Action.
 */

namespace riscv_vector
{

///@brief Actions to perform on the entire Function before running rules in the oppool1 pool
class ActionPluginPrepare
{
  public:
    /// @brief constructor
    /// @param myLogger Logger to use
    explicit ActionPluginPrepare(std::shared_ptr<spdlog::logger> myLogger);
    /// @brief Remove pointless Control and Status Register Heritage entries (aka Phi nodes or MULTIEQUAL nodes)
    /// @param fData context for the function currently being decompiled
    void purgeCsrHeritage(ghidra::Funcdata& fData);
  private:
    /// @brief the logger to use within this class
    std::shared_ptr<spdlog::logger> logger;
};
}

#endif /* RISCV_CSR_HH */