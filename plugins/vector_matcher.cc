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
    // show traits we have deduced
    loopLogger->info("Summary of traits:\n"
        "\tVector stanza begins at 0x{0:x}\n"
        "\telementSize = {1:d}\n"
        "\tmultiplier = {2:d}\n"
        "\tcode size = 0x{3:x}",
        loopStartAddr, elementSize, multiplier, loopEndAddr - loopStartAddr);
    loopLogger->info("\n"
        "\tNumber of Phi nodes affected by loop = {0:d}\n"
        "\tNumber of other UserPcodes = {1:d}\n"
        "\tNumber of arithmetic ops = {2:d}",
        phiNodesAffectedByLoop.size(), otherUserPcodes.size(), numArithmeticOps);
    loopLogger->info("\n"
        "\tNumber of elements is constant = {0:s}\n"
        "\tNumber of elements is variable = {1:s}\n"
        "\tFound simple comparison = {2:s}\n"
        "\tFound unexpected opcode = {3:s}",
        numElementsConstant ? "true" : "false",
        numElementsVariable ? "true" : "false",
        foundSimpleComparison ? "true" : "false",
        foundUnexpectedOp ? "true" : "false");
    loopLogger->info("\n"
        "\tFound other user  opcode = {0:s}\n"
        "\tFound simple flow structure = {1:s}\n"
        "\tFound simple load/store pattern = {2:s}\n"
        "\tFound vector registers match = {3:s}",
        foundOtherUserPcodes ? "true" : "false",
        simpleFlowStructure ? "true" : "false",
        simpleLoadStoreStructure ? "true" : "false",
        vectorRegistersMatch ? "true" : "false");
    loopLogger->info("\n"
        "\tNumber of elements varnode identified = {0:s}\n"
        "\tNumber of elements per loop varnode identified = {1:s}\n"
        "\tVector load address varnode identified = {2:s}\n"
        "\tVector store address varnode identified = {3:s}",
        vNumElem != nullptr ? "true" : "false",
        vNumPerLoop != nullptr ? "true" : "false",
        vLoadVn != nullptr ? "true" : "false",
        vStoreVn != nullptr ? "true" : "false");
}

VectorMatcher::~VectorMatcher()
{

}

bool VectorMatcher::isMemcpy()
{
    return simpleFlowStructure && simpleLoadStoreStructure && foundSimpleComparison &&
        vectorRegistersMatch && (numArithmeticOps >=3) && (!foundUnexpectedOp) &&
        (!foundOtherUserPcodes);
}
int VectorMatcher::transform()
{

    loopLogger->info("Transforming selection into vector_memcpy");
    // todo: compute number of bytes to move, generate a new varnode
    PcodeOp* newOp = insertBuiltin(data, *vsetOp, VECTOR_MEMCPY, vStoreVn, vLoadVn, vNumElem);
    data.opInsertBefore(newOp, vsetOp);

    // trim any leading Phi nodes of references any loop varnodes we are absorbing
    loopLogger->info("Trimming loop varnodes out of leading Phi nodes");
    for (std::vector<PcodeOp*>::iterator it = phiNodesAffectedByLoop.begin();
         it != phiNodesAffectedByLoop.end();
         ++it)
    {
        PcodeOp* phiOp = *it;
        // Delete any varnode references to loop variable varnodes
        for (int slot = 0; slot < phiOp->numInput(); ++slot)
        {
            Varnode *vn = phiOp->getIn(slot);
            PcodeOp *def = vn->getDef();
            if (def != nullptr)
            {
                intb defOffset = def->getAddr().getOffset();
                if (defOffset >= loopStartAddr && defOffset <= loopEndAddr)
                {
                    loopLogger->trace("  deleting slot {0:d} of pcode at 0x{1:x}",
                                        slot, phiOp->getAddr().getOffset());
                    data.opRemoveInput(phiOp, slot);
                }
            }
        }
        if ( phiOp->numInput() == 1)
        {
            loopLogger->info("  fixing Phi node with only one input");
            Varnode *vn = phiOp->getIn(0);
            Varnode* resultVn = phiOp->getOut();
            list<PcodeOp *>::const_iterator begin = resultVn->beginDescend();
            list<PcodeOp *>::const_iterator end = resultVn->endDescend();
            for (auto descendent = begin; descendent != end; ++descendent)
            {
                PcodeOp *descendentOp = *descendent;
                for (int slot = 0; slot < descendentOp->numInput(); ++slot)
                {
                    if (resultVn == descendentOp->getIn(slot))
                    {
                        data.opSetInput(descendentOp, vn, slot);
                    }
                }
            }
        }
    }
    // remove loop pcode ops except for the Phi nodes and our inserted op
    std::list<PcodeOp*>::iterator it = loopBlock->beginOp();
    std::list<PcodeOp*>::iterator lastOp = loopBlock->endOp();
    while (it != lastOp)
    {
        PcodeOp* op = *it;
        ++it;
        if ((op->code() == CPUI_MULTIEQUAL) || op == newOp)
            continue;
        data.opUnlink(op);
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
                else if ((opInfo->isLoadImmediate) && (vLoadImmVn == nullptr))
                {
                    // TODO: vector load immediate instructions should not be found inside a loop
                    vLoadImmVn = op->getIn(1);
                    loopLogger->trace("    VloadImmediate found: numElem={0:d}", vLoadImmVn->getOffset());
                }
                else if (opInfo->isVset || opInfo->isLoad || opInfo->isStore)
                    break;
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
    // use lists instead of vectors to allow for push_back inside iterative loops
    std::list<Varnode *> dependentVarnodesInLoop;
    std::list<Varnode *> dependentVarnodesOutsideLoop;
    std::list<PcodeOp *> opsToFixDependencies;
    std::list<PcodeOp *> opsToVisit(phiNodesAffectedByLoop.begin(), phiNodesAffectedByLoop.end());
    Varnode* vLoopStoreVn = nullptr;
    Varnode* vectorNumElemVn;
    Varnode* vectorLoadRegisterVn;
    Varnode* vectorLoadAddrVn;
    Varnode* vectorStoreRegisterVn;
    Varnode* vectorStoreAddrVn;
    // For all Phi nodes affected by the loop determine the output register and its dependencies.
    for (auto op : opsToVisit)
    {
        if (trace)
        {
            std::stringstream ss;
            op->printRaw(ss);
            loopLogger->trace("Examining context of: {0:s}", ss.str());
        }
        Varnode *resultVn = op->getOut();
        // descendent ops with no return value need to be checked for content but not dependencies.
        bool opIsVoid = (resultVn == nullptr);
        intb offset = op->getAddr().getOffset();
        bool isInsideLoop = (offset >= loopStartAddr) && (offset <= loopEndAddr);
        if (info && !opIsVoid)
        {
            string regName;
            getRegisterName(resultVn, &regName);
            if (regName != "")
            {
                loopLogger->info("Tracing loop dependencies for register result {0:s} with register offset 0x{1:x}",
                                 regName, resultVn->getAddr().getOffset());
            }
            else
            {
                loopLogger->info("Tracing loop dependencies for non-register object with offset 0x{0:x}",
                                 resultVn->getAddr().getOffset());
            }
        }
        if (isInsideLoop)
        {
            loopLogger->trace("  Examining context of op inside the loop:");
            // if this is a vector op, identify the register assignments
            const RiscvUserPcode *opInfo = RiscvUserPcode::getUserPcode(*op);
            if (opInfo != nullptr)
            {
                if (opInfo->isVset)
                {
                    multiplier = opInfo->multiplier;
                    elementSize = opInfo->elementSize;
                    vectorNumElemVn = op->getIn(1);
                    vNumPerLoop = op->getOut();
                    loopLogger->trace("    Vset found: numElementsRegister=0x{0:x}",
                                      vectorNumElemVn->getOffset());
                }
                else if (opInfo->isLoad)
                {
                    vectorLoadRegisterVn = op->getOut();
                    vectorLoadAddrVn = op->getIn(1);
                    loopLogger->trace("    Vload found at 0x{0:x}", op->getAddr().getOffset());
                    loopLogger->trace("    Vload register=0x{0:x}",
                                      vectorLoadRegisterVn->getOffset());
                }
                else if (opInfo->isStore)
                {
                    loopLogger->flush();
                    vectorStoreRegisterVn = op->getIn(1);
                    vectorStoreAddrVn = op->getIn(2);
                    vLoopStoreVn = op->getIn(2);
                    loopLogger->trace("    Vstore found: vector register=0x{0:x}; destination register=0x{1:x}",
                                      vectorStoreRegisterVn->getOffset(), vLoopStoreVn->getOffset());
                }
            }
            if (info && (resultVn != nullptr))
            {
                std::stringstream ss;
                resultVn->printRaw(ss);
                loopLogger->trace("  inloop dependency: {0:s}", ss.str());
            }
        }
        else
        {
            loopLogger->trace("  Examining context of op inside the loop:");
            dependentVarnodesOutsideLoop.push_back(resultVn);
            if (std::find(opsToFixDependencies.begin(), opsToFixDependencies.end(), op) == opsToFixDependencies.end())
                opsToFixDependencies.push_back(op);
            if ((resultVn != nullptr) && info)
            {
                std::stringstream ss;
                resultVn->printRaw(ss);
                loopLogger->trace("  exterior dependency to fix: {0:s}", ss.str());
            }
        }
        if (opIsVoid) continue;
        // Add new dependent ops to visit if this op has a known result
        list<PcodeOp *>::const_iterator begin = resultVn->beginDescend();
        list<PcodeOp *>::const_iterator end = resultVn->endDescend();
        for (auto descendent = begin; descendent != end; ++descendent)
        {
            PcodeOp *descendentOp = *descendent;
            if (trace)
            {
                std::stringstream ss;
                descendentOp->printRaw(ss);
                loopLogger->trace("  Descendent op: {0:s}", ss.str());
            }
            dependentVarnodesInLoop.push_back(resultVn);
            if (std::find(opsToVisit.begin(), opsToVisit.end(), descendentOp) == opsToVisit.end())
                opsToVisit.push_back(descendentOp);
    }
    }
    // do load and store registers match?
    vectorRegistersMatch = (vectorLoadRegisterVn == vectorStoreRegisterVn);
    // find the Phi node defining the initial load address register
    for (auto op: phiNodesAffectedByLoop)
    {
        intb regOffset = op->getOut()->getAddr().getOffset();
        loopLogger->trace("Searching for loop variables referring to register 0x{0:x}",
            regOffset);
        if ((vectorNumElemVn != nullptr) && (regOffset == vectorNumElemVn->getOffset()))
        {
            vNumElem = op->getOut();
        }
        else if ((vectorLoadAddrVn != nullptr) && (regOffset == vectorLoadAddrVn->getOffset()))
        {
            vLoadVn = op->getOut();
        }
        else if ((vectorStoreAddrVn != nullptr) && regOffset == vectorStoreAddrVn->getOffset())
        {
            vStoreVn = op->getOut();
        }
    }
}
}