#include "inspector.hh"
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
    std::stringstream ss;
    //logger->info("Calling ActionPluginPrepare::purgeCsrHeritage, dumping PcodeOps");
    //dumpPcodes(data, logger);

    if (ghidra::inspector->audit_varnodes)
    {
        std::ofstream outFile("/tmp/preAudit.txt");
        ghidra::inspector->auditVarnodes(data, outFile);
        outFile.close();
    }
    ghidra::PcodeOpTree::const_iterator firstOp = data.beginOpAll();
    for (auto iter = firstOp; iter != data.endOpAll(); iter++)
    {
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
                logger->info("\t\t ↑↑↑ Removing this opcode");
                ss.str("");
                op->getOut()->printInfo(ss);
                logger->info("\t\t\tinfo: {0:s}", ss.str());
                ghidra::PcodeOp* modifiableOp = const_cast<ghidra::PcodeOp*>(op);
                data.opUninsert(modifiableOp);
                data.opUnlink(modifiableOp);
            }
        }
    }

    // Now clean up any 'free' varnode inputs and replace them with indirect equivalents.
    //logger->trace("Revised PcodeOps in function:");
    //dumpPcodes(data, logger);
    firstOp = data.beginOpAll();
    for (auto iter = firstOp; iter != data.endOpAll(); iter++)
    {
        const ghidra::PcodeOp* op = iter->second;
        if (op->isDead()) continue;
        for (int slot = 0; slot < op->numInput(); slot++)
        {
            const ghidra::Varnode* vn = op->getIn(slot);
            const ghidra::AddrSpace* addrSpace = vn->getAddr().getSpace();
            if (addrSpace == ghidra::csRegisterAddrSpace)
            {
                op->printRaw(ss);
                logger->info("\t\t  Examining slot {0:d} of PcodeOp: {1:s}", slot, ss.str());
                ss.str("");
                vn->printInfo(ss);
                logger->info("\t\t\t{0:s}", ss.str());
                ss.str("");
                ghidra::Varnode* modifiableVn = const_cast<ghidra::Varnode*>(vn);
                ghidra::Varnode* newVn = data.setInputVarnode(modifiableVn);
                ghidra::PcodeOp* modifiableOp = const_cast<ghidra::PcodeOp*>(op);
                data.opUnsetInput(modifiableOp, slot);
                data.opSetInput(modifiableOp, newVn, slot);
                op->printRaw(ss);
                logger->info("\t\t  Re-examining slot {0:d} of PcodeOp: {1:s}", slot, ss.str());
                ss.str("");
                vn->printInfo(ss);
                logger->info("\t\t\t{0:s}", ss.str());
                ss.str("");
            }
        }
    }
    if (ghidra::inspector->audit_varnodes)
    {
        std::ofstream outFile("/tmp/postAudit.txt");
        ghidra::inspector->auditVarnodes(data, outFile);
        outFile.close();
    }
    logger->flush();
}
}