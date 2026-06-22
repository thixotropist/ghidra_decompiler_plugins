#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/type.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/action.hh"

#include "riscv.hh"
#include "riscv_sleigh.hh"
#include "action_prepare.hh"

namespace riscv_vector
{

// static class objects
ghidra::Varnode* ActionPluginPrepare::vlenb_constant_vn;
std::map<uint32_t, uint32_t> ActionPluginPrepare::replacement_values;

void ActionPluginPrepare::static_init()
{
    vlenb_constant_vn = nullptr;
    // Force VLENB to a constant value
    replacement_values.insert({{vlenbRegisterOffset, 32}});
}
ghidra::int4 ActionPluginPrepare::apply(ghidra::Funcdata &data)
{
    ghidra::pLogger->trace("Applying ActionPluginPrepare");
    std::stringstream ss;

    if (ghidra::inspector->audit_varnodes)
    {
        std::ofstream outFile("/tmp/preAudit.txt");
        ghidra::inspector->auditVarnodes(data, outFile);
        outFile.close();
    }

    std::vector<ghidra::PcodeOp*> opsToDelete;
    std::ranges::subrange viewOps{data.beginOpAll(), data.endOpAll()};
    for (auto [seqNum,op] : viewOps)
    {
        ghidra::OpCode opcode = op->code();
        if ((opcode == ghidra::CPUI_COPY) ||
            (opcode == ghidra::CPUI_MULTIEQUAL) ||
            (opcode == ghidra::CPUI_INDIRECT))
        {
            // first scan PcodeOps for which the output Varnode is a CSR
            if ((op->getOut() != nullptr) &&
                (op->getOut()->getAddr().getSpace() == ghidra::csRegisterAddrSpace))
            {
                // treat all CSR ops as non-heritaged
                ghidra::intb addr = op->getAddr().getOffset();
                if (ghidra::info)
                {
                    int opcode_as_int = opcode;
                    op->printRaw(ss);
                    ghidra::pLogger->info("\t0x{0:x}: [{1:d}] {2:s}", addr, opcode_as_int, ss.str());
                    ghidra::pLogger->info("\t\t ↑↑↑ Removing this opcode");
                    ss.str("");
                    op->getOut()->printInfo(ss);
                    ghidra::pLogger->info("\t\t\tinfo: {0:s}", ss.str());
                    ss.str("");
                }
                ghidra::PcodeOp* modifiableOp = const_cast<ghidra::PcodeOp*>(op);
                opsToDelete.push_back(modifiableOp);
                count++;
                continue;
            }
        }
        // Next scan for any CSR varnodes and optionally replace them
        if (op->isDead()) continue;
        for (int slot = 0; slot < op->numInput(); slot++)
        {
            const ghidra::Varnode* vn = op->getIn(slot);
            const ghidra::AddrSpace* addrSpace = vn->getAddr().getSpace();
            if (addrSpace == ghidra::csRegisterAddrSpace)
            {
                if (ghidra::trace)
                {
                    op->printRaw(ss);
                    ghidra::pLogger->trace("\t\t  Examining slot {0:d} of PcodeOp: {1:s}", slot, ss.str());
                    ss.str("");
                    vn->printInfo(ss);
                    ghidra::pLogger->trace("\t\t\t{0:s}", ss.str());
                    ss.str("");
                }
                ghidra::intb offset = vn->getAddr().getOffset();
                if (offset == vlenbRegisterOffset)
                {
                    // generate a constant value replacement if we don't already have one
                    if (vlenb_constant_vn == nullptr)
                    {
                        vlenb_constant_vn = data.newConstant(4, replacement_values[vlenbRegisterOffset]);
                    }
                    ghidra::PcodeOp* modifiableOp = const_cast<ghidra::PcodeOp*>(op);
                    data.opUnsetInput(modifiableOp, slot);
                    data.opSetInput(modifiableOp, vlenb_constant_vn, slot);
                    if (ghidra::info)
                    {
                        op->printRaw(ss);
                        ghidra::pLogger->info("\t\t  Replaced slot {0:d} of PcodeOp: {1:s}", slot, ss.str());
                        ss.str("");
                        ghidra::pLogger->info("\t\t\t{0:s}", ss.str());
                        ss.str("");
                    }
                    count++;
                    continue;
                }
            }
        }
    }
    // Remove any opcodes marked for deletion
    for (auto op: opsToDelete)
    {
        data.opUninsert(op);
        data.opUnlink(op);
    }
    // Now clean up any 'free' varnode inputs and replace them with indirect equivalents.
    std::ranges::subrange allOps{data.beginOpAll(), data.endOpAll()};
    for (auto [seqNum,op] : allOps)
    {
        if (op->isDead()) continue;
        for (int slot = 0; slot < op->numInput(); slot++)
        {
            const ghidra::Varnode* vn = op->getIn(slot);
            if ((vn->getAddr().getSpace() == ghidra::csRegisterAddrSpace) && vn->isFree())
            {
                if (ghidra::info)
                {
                    vn->printRaw(ss);
                    ghidra::pLogger->info("Changing Varnode {0:s} from free to input", ss.str());
                    ss.str("");
                }
                ghidra::PcodeOp* modifiableOp = const_cast<ghidra::PcodeOp*>(op);
                data.opUnsetInput(modifiableOp, slot);
                ghidra::Varnode* modifiableVn = const_cast<ghidra::Varnode*>(vn);
                ghidra::Varnode* newVn = data.setInputVarnode(modifiableVn);
                data.opSetInput(modifiableOp, newVn, slot);
                count++;
                if (ghidra::info)
                {
                    op->printRaw(ss);
                    ghidra::pLogger->info("\tnew PcodeOp is {0:s}", ss.str());
                    ss.str("");
                }
            }
        }
    }

    if (ghidra::inspector->audit_varnodes)
    {
        std::ofstream outFile("/tmp/postAudit.txt");
        ghidra::inspector->auditVarnodes(data, outFile);
        outFile.close();
    }
    ghidra::pLogger->flush();
    return 0;
}
}