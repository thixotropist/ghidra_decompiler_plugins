#ifndef RISCV_SLEIGH_HH_
#define RISCV_SLEIGH_HH_
#include "riscv.hh"

/**
 * @brief Collect definitions and tests that depend on specifics of
 * this Architecture's SLEIGH definitions
 */

namespace ghidra
{
extern AddrSpace* csRegisterAddrSpace; /// The address space holding RISCV control and status registers
static const uintb vlRegisterIndex = 0x6100; /// The offset in csreg space given to the "vl" register
/**
 * @brief Initialize any global objects dependent upon SLEIGH
 */
void riscv_sleigh_init(ghidra::Architecture* arch);
/**
 * @brief Inspect identifiers that may change with SLA file evolutions
 * @param arch The Architecture conveying these SLA file contents
 * @param ss A stringstream to receive the report
 */
void riscv_sleigh_inspect(ghidra::Architecture* arch, std::stringstream& ss);
}
#endif /* RISCV_SLEIGH_HH_ */
