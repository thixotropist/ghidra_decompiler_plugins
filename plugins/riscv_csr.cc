#include "riscv_csr.hh"
#include "riscv_sleigh.hh"

namespace riscv_vector
{
ActionPluginPrepare::ActionPluginPrepare(std::shared_ptr<spdlog::logger> myLogger) :
    logger(myLogger)
{
    logger->info("Initializing ActionPluginPrepare");
}

void ActionPluginPrepare::purgeCsrHeritage(ghidra::Funcdata& data)
{
    logger->info("Calling ActionPluginPrepare::purgeCsrHeritage, dumping PcodeOps");
    ghidra::PcodeOpTree::const_iterator firstOp =	data.beginOpAll();
    for (auto iter = firstOp; iter != data.endOpAll(); iter++)
    {
        std::stringstream ss;
        const ghidra::PcodeOp* op = iter->second;
        ghidra::OpCode opcode = op->code();
        if ((opcode == ghidra::CPUI_COPY) ||
            (opcode == ghidra::CPUI_MULTIEQUAL) ||
            (opcode == ghidra::CPUI_INDIRECT)
        )
        {
            int opcode_as_int = opcode;
            if (op->getOut() == nullptr)
                continue;
            const ghidra::AddrSpace* addrSpace = op->getOut()->getAddr().getSpace();
            if ((addrSpace == ghidra::stackAddrSpace) ||
                (addrSpace == ghidra::ramAddrSpace))
                continue;
            ghidra::intb addr = op->getAddr().getOffset();
            op->printRaw(ss);
            ghidra::pLogger->trace("\t0x{0:x}: [{1:d}] {2:s}", addr, opcode_as_int, ss.str());
            ss.str("");
            if (addrSpace == ghidra::csRegisterAddrSpace)
            {
                logger->info("\tRemoving this opcode");
                ghidra::PcodeOp* modifiableOp = const_cast<ghidra::PcodeOp*>(op);
                data.opUninsert(modifiableOp);
                data.opUnlink(modifiableOp);
            }
        }
    }
}
}