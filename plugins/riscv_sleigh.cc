#include "riscv_sleigh.hh"
#include "riscv.hh"

/**
 * @brief Collect definitions and tests that depend on specifics of
 * this Architecture's SLEIGH definitions
 */

namespace ghidra
{
AddrSpace* csRegisterAddrSpace; ///< The non-standard Address space built to contain csreg definitions

void riscv_sleigh_init(ghidra::Architecture* arch)
{
    csRegisterAddrSpace = arch->getSpaceByName("csreg");
    pLogger->trace("Identified vl register offset as 0x{0:x}", vlRegisterIndex);
}
void riscv_sleigh_inspect(ghidra::Architecture* arch, std::stringstream& ss)
{
    ss << "Inspecting SLEIGH objects for this architecture" << std::endl;
    // show the Address space IDs
    ss << "Standard and SLA-specific Address spaces by index:" << std::endl;
    for (int i = 0; i < arch->numSpaces(); i++)
    {
        ss << "\t" << std::dec << i << " : " << arch->getSpace(i)->getName() << std::endl;
    }
    // The csreg space is specific to our SLEIGH definitions, and is technically a part of the OtherSpace
    ss << "Control and Status Register space is of type "
        << static_cast<int>(csRegisterAddrSpace->getType()) << std::endl;
    const Translate* trans = csRegisterAddrSpace->getTrans();
    ss << "Note that Control and Status Registers have no name."
        "They do have symbol names pointing into the csreg address space" << std::endl;
    std::map< ghidra::VarnodeData, std::string > reglist;
    trans->getAllRegisters(reglist);
    ss << "Registers by index:" << std::endl;
    for (auto const& [vndata, name] : reglist)
    {
        ss << "\t" << std::hex << vndata.offset << ":" << name << std::dec << std::endl;
    }
}
}
