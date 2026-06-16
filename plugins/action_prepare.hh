#ifndef __ACTION_PREPARE_HH__
#define __ACTION_PREPARE_HH__

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/type.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/action.hh"

namespace riscv_vector
{
/**
 * @file action_prepare.hh
 *
 * @brief Provide an Action to adjust CSR values and heritage
 *
 */
class ActionPluginPrepare : public ghidra::Action {
  public:
    /// @brief The CSR wordsize, probably the same as the scalar register size
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

    explicit ActionPluginPrepare(const std::string &g) : ghidra::Action(0,"pluginrules",g) {}       ///< Constructor
    static void static_init(); ///< Static initialization
    virtual void reset(ghidra::Funcdata &data) {}
    virtual ghidra::Action *clone(const ghidra::ActionGroupList &grouplist) const {
        if (!grouplist.contains(getGroup())) return (Action *)0;
        return new ActionPluginPrepare(getGroup());
    }
    virtual ghidra::int4 apply(ghidra::Funcdata &data);
  private:
    /// @brief map of constant CSRs to their replacement values
    static std::map<uint32_t, uint32_t> replacement_values;
    /// @brief A constant Varnode to use in place of `VLENB` varnodes.
    static ghidra::Varnode* vlenb_constant_vn;

};
}
#endif /*__ACTION_PREPARE_HH__ */