#include "riscv_sleigh.hh"
#include "riscv.hh"

/**
 * @brief Collect definitions and tests that depend on specifics of
 * this Architecture's SLEIGH definitions
 */

namespace ghidra
{
AddrSpace* csRegisterAddrSpace; ///< The non-standard Address space built to contain csreg definitions

void riscv_sleigh_init(ghidra::Architecture* thisArch)
{
    pLogger->info("Attempting thisArch->getSpaceByName(\"csreg\")");
    pLogger->flush();
    csRegisterAddrSpace = thisArch->getSpaceByName("csreg");
    if (csRegisterAddrSpace == nullptr)
    {
        pLogger->error("Unable to find csreg address space");
        pLogger->flush();
    }
    pLogger->trace("Identified vl register offset as 0x{0:x}", vlRegisterIndex);
    pLogger->trace("csRegisterAddrSpace index is {0:d}", csRegisterAddrSpace->getIndex());
    pLogger->flush();
}
void riscv_sleigh_inspect(ghidra::Architecture* thisArch, std::stringstream& ss)
{
    ss << "Inspecting SLEIGH objects for this architecture" << std::endl;
    // show the Address space IDs
    ss << "Standard and SLA-specific Address spaces by index:" << std::endl;
    for (int i = 0; i < thisArch->numSpaces(); i++)
    {
        ss << "\t" << std::dec << i << " : " << thisArch->getSpace(i)->getName() << std::endl;
    }
}
}
