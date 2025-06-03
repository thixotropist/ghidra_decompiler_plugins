#include <string>
#include <sstream>
#include <set>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"

#include "riscv.hh"
#include "vector_matcher.hh"
#include "diagnostics.hh"
#include "utility.hh"

namespace ghidra
{

PhiNode::PhiNode(intb reg, Varnode* v1, Varnode* v2, Varnode* v3)
{
    registerOffset = reg;
    varnodes.push_back(v1);
    varnodes.push_back(v2);
    if (v3 != nullptr)
    varnodes.push_back(v3);
}

VectorMatcher::VectorMatcher(Funcdata& fData, PcodeOp* initialVsetOp) :
    data(fData),
    loopFound(false),
    loopStartAddr(0),
    loopEndAddr(0),
    numElementsConstant(false),
    numElementsVariable(false),
    foundSimpleComparison(false),
    foundUnexpectedOp(false),
    foundOtherUserPcodes(false),
    simpleFlowStructure(true),
    simpleLoadStoreStructure(true),
    vectorRegistersMatch(false),
    numArithmeticOps(0),
    multiplier(1),
    elementSize(0),
    vsetOp(initialVsetOp),
    vNumElem(nullptr),
    vNumPerLoop(nullptr),
    vLoadVn(nullptr),
    vLoadImmVn(nullptr),
    vStoreVn(nullptr),
    analysisEnabled(false),
    trace(loopLogger->should_log(spdlog::level::trace)),
    info(loopLogger->should_log(spdlog::level::info))
{
    if (vsetOp == nullptr) return;
    // get basic info on the vsetop trigger
    const RiscvUserPcode* vsetInfo = RiscvUserPcode::getUserPcode(*vsetOp);
    numElementsConstant = vsetInfo->isVseti;
    numElementsVariable = vsetInfo->isVset;
    multiplier = vsetInfo->multiplier;
    elementSize = vsetInfo->elementSize;
    vNumElem = vsetOp->getIn(1);
    // determine if we have a loop and if so, where does it start and stop
    collect_control_flow_data();
    // terminate construction if this vset op doesn't start a loop
    if (!loopFound) return;
    loopLogger->info("Analyzing potential vector stanza at 0x{0:x}",
        loopStartAddr);
    loopLogger->info("Analysis (part 1):\n"
            "\telementSize = {0:d}\n"
            "\tmultiplier = {1:d}\n"
            "\tsize = 0x{2:x}",
            elementSize, multiplier, loopEndAddr - loopStartAddr);
    // Phi (or Multiequal nodes) provide the locations at which
    // registers and memory locations are set. They are found at the top of a block
    // and are essential in determining heritages and dependencies
    collect_phi_nodes();
    // Identify key registers and vector operations within a loop,
    // checking for unexpected elements that may veto a match
    examine_loop_pcodeops();
    // Follow dependencies of phi nodes within the loop to identify
    // source and destination pointer registers and the counter register
    collect_loop_registers();
}

VectorMatcher::~VectorMatcher()
{

}

bool VectorMatcher::isMemcpy()
{
    return loopFound &&
        simpleFlowStructure && simpleLoadStoreStructure && foundSimpleComparison &&
        vectorRegistersMatch && (numArithmeticOps >=3) && (!foundUnexpectedOp) &&
        (!foundOtherUserPcodes);
}
int VectorMatcher::transform()
{
    loopLogger->info("Transforming selection into vector_memcpy");
    // todo: compute number of bytes to move, generate a new varnode
    PcodeOp* newOp = insertBuiltin(data, *vsetOp, VECTOR_MEMCPY, vStoreVn, vLoadVn, vNumElem);
    data.opInsertBefore(newOp, vsetOp);

    // purge any descendents of the deleted varnodes
    loopLogger->info("Trimming dependencies");
    loopLogger->trace("Searching for varnodes between {0:x} and {1:x}", loopStartAddr, loopEndAddr);
    std::set<PcodeOp*>::iterator it = pcodeOpDependencies.begin();
    while (it != pcodeOpDependencies.end())
    {
        PcodeOp* op = *it;
        loopLogger->trace("Pcode to be trimmed has {0:d} inputs at address 0x{1:x}",
            op->numInput(), op->getAddr().getOffset());
        displayPcodeOp(*op, "Pcode to be trimmed", false);
        int lastSlot = op->numInput() - 1;
        for (int i = lastSlot; i >= 0; --i)
        {
            Varnode* v = op->getIn(i);
            if ((v == nullptr) || (v->getDef() == nullptr))
            {
                loopLogger->warn("Tried to process a null varnode or varnode without a parent pcodeop");
                continue;
            }
            intb offset = v->getDef()->getAddr().getOffset();
            loopLogger->info("Searching for deleted varnodes: offset=0x{0:x}, addr=0x{1:x}",
                offset, v->getAddr().getOffset());
            if ((offset >= loopStartAddr) && (offset <= loopEndAddr))
            {
                data.opRemoveInput(op, i);
                loopLogger->trace("  deleting slot {0:d} of pcode at 0x{1:x}",
                    i, op->getAddr().getOffset());
            }
            loopLogger->flush();
        }
        displayPcodeOp(*op, "Pcode after trimming", false);
        ++it;
    }
    for (auto it: pcodeOpSelection)
    {
        data.opUnlink(it);
    }
    return 1;
}

void VectorMatcher::collect_control_flow_data()
{
    loopStartAddr = vsetOp->getAddr().getOffset();
    loopBlock = vsetOp->getParent();
    Address lastAddr = loopBlock->getStop();
    loopEndAddr = lastAddr.getOffset();
    PcodeOp* lastOp = loopBlock->lastOp();
    bool isBranch = lastOp->isBranch();
    // this block forms a loop if it starts with a vset and ends
    // with a conditional branch back to the start
    if (isBranch && (lastOp->code() == CPUI_CBRANCH))
    {
        intb branchTarget = lastOp->getIn(0)->getAddr().getOffset();
        if (branchTarget == loopStartAddr)
        {
            simpleFlowStructure = true;
            loopFound = true;
            foundSimpleComparison = true;
        }
        else
        {
            simpleFlowStructure = false;
            loopFound = false;
            foundSimpleComparison = false;
        }
    }
    if (loopFound)
    {
        loopLogger->info("Loop instruction range: 0x{0:x} to 0x{1:x}",
            loopStartAddr, loopEndAddr);
        loopLogger->info("loopFound = {0:d}; simpleFlowStructure = {1:d}; "
                         "foundSimpleComparison = {2:d}",
                         loopFound, simpleFlowStructure, foundSimpleComparison);
    }
}

void VectorMatcher::collect_phi_nodes()
{
    PcodeOpTree::const_iterator iter = data.beginOp(vsetOp->getAddr());
    PcodeOpTree::const_iterator enditer = data.endOp(vsetOp->getAddr());
    // This loop collects PcodeOps that share an instruction address
    // with the trigger vsetOp.
    loopLogger->trace("  Iterating over vset phi pcodes");
    while(iter!=enditer) {
        // iter points at a (SeqNum, PcodeOp*) pair
        PcodeOp *op = (*iter).second;
         ++iter;
         if (op->code() == CPUI_MULTIEQUAL)
         {
            if (trace)
            {
                std::stringstream ss;
                op->printRaw(ss);
                loopLogger->trace("  Analysis of Phi node: {0:s}",
                    ss.str());
            }
            int numArgs = op->numInput();
            //intb reg = op->getOut()->getOffset();
            for (int slot = 0; slot < numArgs; ++slot)
            {
                // where does this arg get written?
                if (trace)
                {
                    std::stringstream ss;
                    op->getIn(slot)->printRaw(ss);
                    loopLogger->trace("  Analysis of Varnode in slot {0:d}: {1:s}",
                        slot, ss.str());
                }
                PcodeOp* definingOp = op->getIn(slot)->getDef();
                if (definingOp != nullptr)
                {
                    intb offset = definingOp->getAddr().getOffset();
                    if ((offset >= loopStartAddr) && (offset <= loopEndAddr))
                    {
                        // we might want to record the slot number and register
                        phiNodesAffectedByLoop.push_back(op);
                    }
                }
            }
         }
    }
    loopLogger->trace("  Found {0:d} Phi nodes affected by the loop", phiNodesAffectedByLoop.size());
}
void VectorMatcher::examine_loop_pcodeops()
{
    std::list<PcodeOp*>::iterator it = loopBlock->beginOp();
    std::list<PcodeOp*>::iterator lastOp = loopBlock->endOp();
    Varnode* vectorLoadRegisterVn = nullptr;
    Varnode* vectorStoreRegisterVn = nullptr;
    bool analysisFailed = false;
    int conditional_branches = 0;
    loopLogger->trace("Beginning loop pcode analysis");
    while (it != lastOp && !analysisFailed)
    {
        PcodeOp* op = *it;
        ++it;
        intb opOffset = op->getAddr().getOffset();
        if (trace)
        {
            std::stringstream ss;
            op->printRaw(ss);
            loopLogger->trace("  PcodeOp at 0x{0:x}: {1:s}",
                opOffset, ss.str());
        }
        switch(op->code())
        {
          case CPUI_BRANCH:
            simpleFlowStructure = false;
            break;
          case CPUI_CBRANCH:
            // there should only be one of these
            ++conditional_branches;
            break;
          case CPUI_BRANCHIND:
            // indirect branches are unexpected
            simpleFlowStructure = false;
            break;
          case CPUI_CALL:
            // function calls are unexpected
            simpleFlowStructure = false;
            analysisFailed = true;
            break;
          case CPUI_RETURN:
          // function returns are unexpected
            simpleFlowStructure = false;
            analysisFailed = true;
            break;
          case CPUI_INT_NOTEQUAL:
            // loop condition test
            foundSimpleComparison = true;
            break;
          case CPUI_INT_ADD:
            // integer adds are common pointer ops
            ++numArithmeticOps;
            break;
          case CPUI_INT_SUB:
            // integer subtracts are common counter decrements
            ++numArithmeticOps;
            break;
          case CPUI_PTRADD:
            // integer adds are common pointer ops
            ++numArithmeticOps;
            break;
          case CPUI_INT_MULT:
            // Probably a multiply by -1
            break;
          case CPUI_INT_2COMP:
            // Twos complement, sometimes part of a subtraction
            break;
          case CPUI_CAST:
            // Ignore cast pcodes for now
            break;
          case CPUI_MULTIEQUAL:
            // handled separately at the top of the loop
            break;
          case CPUI_CALLOTHER:
          {
                const RiscvUserPcode* opInfo = RiscvUserPcode::getUserPcode(*op);
                if (opInfo == nullptr)
                {
                    // may also be other builtin pcodes
                    foundOtherUserPcodes = true;
                }
                else if (opInfo->isVset)
                {
                    multiplier = opInfo->multiplier;
                    elementSize = opInfo->elementSize;
                    vNumElem = op->getIn(1);
                    vNumPerLoop = op->getOut();
                    loopLogger->trace("    Vset found: numElementsRegister=0x{0:x}",
                        vNumElem->getOffset());
                }
                else if ((opInfo->isLoad) && (vLoadVn == nullptr))
                {
                    vectorLoadRegisterVn = op->getOut();
                    loopLogger->trace("    Vload found at 0x{0:x}", op->getAddr().getOffset());
                    loopLogger->flush();
                    if (vectorLoadRegisterVn == nullptr)
                    {
                        loopLogger->warn("    Vload at 0x{0:x} has no output!",
                            op->getAddr().getOffset());
                        displayPcodeOp(*op, "VLoad with no output", true);
                    }
                    else
                        loopLogger->trace("    Vload register=0x{0:x}",
                            vectorLoadRegisterVn->getOffset());
                }
                else if ((opInfo->isLoadImmediate) && (vLoadImmVn == nullptr))
                {
                    // TODO: vector load immediate instructions should not be found inside a loop
                    vLoadImmVn = op->getIn(1);
                    loopLogger->trace("    VloadImmediate found: numElem={0:d}", vLoadImmVn->getOffset());
                }
                else if ((opInfo->isStore) && (vStoreVn == nullptr))
                {
                    vectorStoreRegisterVn = op->getIn(1);
                    Varnode* vLoopStoreVn = op->getIn(2);
                    loopLogger->trace("    Vstore found: vector register=0x{0:x}; destination register=0x{1:x}",
                        vectorStoreRegisterVn->getOffset(), vLoopStoreVn->getOffset());
                }
                else
                {
                    foundOtherUserPcodes = true;
                    otherUserPcodes.push_back(op);
                    std::stringstream ss;
                    op->printRaw(ss);
                    loopLogger->trace("    Unexpected user pcode found at 0x{0:x}: {1:s}",
                        opOffset, ss.str());
                }
            }
            break;
          default:
            {
                foundUnexpectedOp = true;
                int opcode = op->code();
                loopLogger->warn("    Unexpected op found in analysis: {0:d}", opcode);
            }
        }
    }
}
void VectorMatcher::collect_loop_registers()
{
    std::list<Varnode*> dependentVarnodesInLoop;
    std::list<Varnode*> dependentVarnodesOutsideLoop;
    std::list<PcodeOp*> opsToVisit(phiNodesAffectedByLoop.begin(), phiNodesAffectedByLoop.end());
    std::list<PcodeOp*> opsToFixDependencies;
    for (auto op: opsToVisit)
    {
        Varnode* phiResult = op->getOut();
        const Translate *trans = phiResult->getAddr().getSpace()->getTrans();
        string regName = trans->getRegisterName(phiResult->getAddr().getSpace(), phiResult->getAddr().getOffset(), 8);
        loopLogger->info("Tracing loop dependencies for Phi node register 0x{0:x} aka {1:s}",
            phiResult->getAddr().getOffset(), regName);

        list<PcodeOp*>::const_iterator begin = phiResult->beginDescend();
        list<PcodeOp*>::const_iterator end = phiResult->endDescend();
        for (auto descendent = begin; descendent != end; ++descendent)
        {
            std::stringstream ss;
            (*descendent)->printRaw(ss);
            loopLogger->trace("  Descendent op: {0:s}", ss.str());
            Varnode* vn = (*descendent)->getOut();
            if (vn == nullptr) continue;
            intb offset = vn->getDef()->getAddr().getOffset();
            if (offset >= loopStartAddr && offset<= loopEndAddr)
            {
                dependentVarnodesInLoop.push_back(vn);
                if (std::find(opsToVisit.begin(), opsToVisit.end(), *descendent) == opsToVisit.end())
                    opsToVisit.push_back(*descendent);
                std::stringstream ss;
                vn->printRaw(ss);
                loopLogger->trace("  inloop dependency: {0:s}", ss.str());
            }
            else{
                dependentVarnodesOutsideLoop.push_back(vn);
                if (std::find(opsToFixDependencies.begin(), opsToFixDependencies.end(), *descendent) == opsToFixDependencies.end())
                    opsToFixDependencies.push_back(*descendent);
                std::stringstream ss;
                vn->printRaw(ss);
                loopLogger->trace("  exterior dependency to fix: {0:s}", ss.str());
            }
        }
    }
}
}