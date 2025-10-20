/**
 * @file vector_ops.cc
 * @author thixotropist
 * @brief Model RISC-V vector operands
 * @date 2025-10-07
 *
 * @copyright Copyright (c) 2025
 *
 */
#include "framework.hh"
#include "vector_ops.hh"
#include "riscv.hh"

namespace riscv_vector{

VectorOperand::~VectorOperand()
{
    for (auto st: stripes) delete st;
    stripes.clear();
}

void VectorStripe::setVregister(const ghidra::Varnode* const vn)
{
    vector_register = vn->getOffset();
}

void VectorStripe::setBaseAddr(const ghidra::Varnode* const vn)
{
    pointer_register = vn->getOffset();
}

VectorFunction::VectorFunction() :
    typ(unknown),
    name("pending"),
    loopFlags(0x0),
    numLoopVectorOps(0),
    numArithmeticOps(0),
    foundOtherUserPcodes(false),
    simpleFlowStructure(false),
    foundSimpleComparison(false),
    foundUnexpectedOpcode(false)
{
    ghidra::pLogger->trace("Adding VectorFunction instruction handlers to operations map");

    // instructions found in many vector stanzas, starting with vector_memcpy
    operations[ghidra::riscvNameToGhidraId["vle8_v"]] =
        [this](int a, const ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vle8_v instruction handler");
            addLoadOperand(op);
        };
    operations[ghidra::riscvNameToGhidraId["vse8_v"]] =
        [this](int a, const ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vse8_v instruction handler");
            addStoreOperand(op);
        };
    // instructions found in vector_strlen stanzas
    operations[ghidra::riscvNameToGhidraId["vle8ff_v"]] =
        [this](int a, const ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vle8ff_v instruction handler");
            this->loopFlags |= ghidra::RISCV_VEC_INSN_FAULT_ONLY_FIRST;
            addLoadOperand(op);
        };
    operations[ghidra::riscvNameToGhidraId["vmseq_vi"]] =
        [this](int a, const ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vmseq_vi instruction handler");
            ///@todo: figure out how to represent this operation as a VectorOperator
        };
    operations[ghidra::riscvNameToGhidraId["vfirst_m"]] =
        [this](int a, const ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vfirst_m instruction handler");
            ///@todo: figure out how to represent this operation as a VectorOperator
        };
}

void VectorFunction::addLoadOperand(const ghidra::PcodeOp* const op)
{
    const ghidra::RiscvUserPcode* opInfo = ghidra::RiscvUserPcode::getUserPcode(*op);
    loopFlags |= opInfo->flags;
    VectorStripe* stripe = new VectorStripe;
    stripe->setVregister(op->getOut());
    stripe->setBaseAddr(op->getIn(1));
    ///@todo Where do we consolidate compatible stripes into a single operand?
    VectorOperand* operand = new VectorOperand(VectorOperand::load);
    operand->stripes.push_back(stripe);
    operands.push_back(operand);
}

void VectorFunction::addStoreOperand(const ghidra::PcodeOp* const op)
{
    const ghidra::RiscvUserPcode* opInfo = ghidra::RiscvUserPcode::getUserPcode(*op);
    loopFlags |= opInfo->flags;
    VectorStripe* stripe = new VectorStripe;
    stripe->setVregister(op->getIn(1));
    stripe->setBaseAddr(op->getIn(2));
    ///@todo Where do we consolidate compatible stripes into a single operand?
    VectorOperand* operand = new VectorOperand(VectorOperand::store);
    operand->stripes.push_back(stripe);
    operands.push_back(operand);
}

bool VectorFunction::invokeVectorOpHandler(ghidra::PcodeOp* op)
{
    const ghidra::RiscvUserPcode* opInfo = ghidra::RiscvUserPcode::getUserPcode(*op);
    ghidra::pLogger->trace("Looking for instruction handler for {0:s} with id {1:d}",
        opInfo->asmOpcode, opInfo->ghidraOp);
    auto f = operations.find(opInfo->ghidraOp);
    if (f != operations.end())
    {
        ghidra::pLogger->trace("Found the instruction handler, executing:");
        std::function<void(int ghidraOp, ghidra::PcodeOp* op)> handler = f->second;
        (handler)(opInfo->ghidraOp, op);
        return true;
    }
    return false;
}

void VectorFunction::log()
{
    ghidra::pLogger->info("VectorFunction info:\n"
        "\tname = {0:s}\n"
        "\ttype = {1:s}\n"
        "\tNumber of operands = {2:d}\n"
        "\tLoop Flags = 0x{3:x}",
        name, fTypeToString[static_cast<int>(typ)], operands.size(), loopFlags);
    int i = 0;
    for (const auto po: operands)
    {
        int j = 0;
        for (const auto ps: po->stripes)
        {
            std::string vecRegisterName;
            ghidra::getRegisterName(ps->vector_register, &vecRegisterName);
            std::string ptrRegisterName;
            ghidra::getRegisterName(ps->pointer_register, &ptrRegisterName);

            ghidra::pLogger->info("\tOperand {0:d}, Type {1:s}, Stripe {2:d}:\n"
                "\t\tVector_register = {3:s}\n"
                "\t\tPointer_register = {4:s}",
                i, po->opTypeToString[static_cast<int>(po->opType)], j, vecRegisterName, ptrRegisterName);
            ++j;
        }
        ++i;
    }
}

void VectorFunction::examine_loop_pcodeops(const ghidra::BlockBasic* loopBlock)
{
    bool trace = ghidra::pLogger->should_log(spdlog::level::trace);
    // bool info = ghidra::pLogger->should_log(spdlog::level::info);
    std::list<ghidra::PcodeOp*>::const_iterator it = loopBlock->beginOp();
    std::list<ghidra::PcodeOp*>::const_iterator lastOp = loopBlock->endOp();
    bool analysisFailed = false;
    int conditional_branches = 0;
    ghidra::pLogger->trace("Beginning loop pcode analysis");
    while (it != lastOp && !analysisFailed)
    {
        ghidra::PcodeOp* op = *it;
        ++it;
        ghidra::intb opOffset = op->getAddr().getOffset();
        if (trace)
        {
            std::stringstream ss;
            op->printRaw(ss);
            ghidra::pLogger->trace("  PcodeOp at 0x{0:x}: {1:s}",
                opOffset, ss.str());
        }
        switch(op->code())
        {
          case ghidra::CPUI_BRANCH:
            simpleFlowStructure = false;
            break;
          case ghidra::CPUI_CBRANCH:
            // there should only be one of these
            ++conditional_branches;
            break;
          case ghidra::CPUI_BRANCHIND:
            // indirect branches are unexpected
            simpleFlowStructure = false;
            break;
          case ghidra::CPUI_CALL:
            // function calls are unexpected
            simpleFlowStructure = false;
            analysisFailed = true;
            break;
          case ghidra::CPUI_RETURN:
            // function returns are unexpected
            simpleFlowStructure = false;
            analysisFailed = true;
            break;
          case ghidra::CPUI_INT_NOTEQUAL:
            // loop condition test
            foundSimpleComparison = true;
            break;
          case ghidra::CPUI_INT_ADD:
            // integer adds are common pointer ops
            ++numArithmeticOps;
            break;
          case ghidra::CPUI_INT_SUB:
            // integer subtracts are common counter decrements
            ++numArithmeticOps;
            break;
          case ghidra::CPUI_PTRADD:
            // integer adds are common pointer ops
            ++numArithmeticOps;
            break;
          case ghidra::CPUI_INT_MULT:
            // Probably a multiply by -1
            break;
          case ghidra::CPUI_INT_2COMP:
            // Twos complement, sometimes part of a subtraction
            break;
          case ghidra::CPUI_CAST:
            // Ignore cast pcodes for now
            break;
          case ghidra::CPUI_MULTIEQUAL:
            // handled separately at the top of the loop
            break;
          case ghidra::CPUI_CALLOTHER:
            {
                const ghidra::RiscvUserPcode* opInfo = ghidra::RiscvUserPcode::getUserPcode(*op);
                if (opInfo == nullptr)
                {
                    // may also be other builtin pcodes
                    foundOtherUserPcodes = true;
                }
                else if (opInfo->isVset)
                {
                    ++numLoopVectorOps;
                    break;
                }
                else
                {
                    if (opInfo->isVectorOp)
                    {
                        ++numLoopVectorOps;
                        ghidra::pLogger->trace("Invoking a VectorFunction instruction handler");
                        invokeVectorOpHandler(op);
                    }
                    else
                    {
                        foundOtherUserPcodes = true;
                        otherUserPcodes.push_back(op);
                        std::stringstream ss;
                        op->printRaw(ss);
                        ghidra::pLogger->trace("    Unexpected user pcode found at 0x{0:x}: {1:s}",
                            opOffset, ss.str());
                    }
                }
            }
            break;
            default:
            {
                foundUnexpectedOpcode = true;
                int opcode = op->code();
                ghidra::pLogger->warn("    Unexpected op found in analysis: {0:d}", opcode);
            }
        }
    }
}

VectorFunction::~VectorFunction()
{
    for (auto op: operands) delete op;
    operands.clear();
}
}