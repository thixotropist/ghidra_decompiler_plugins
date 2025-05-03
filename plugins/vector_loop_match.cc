#include <string>
#include <set>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"

#include "riscv.hh"
#include "vector_loop_match.hh"
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

Varnode* VectorLoopMatch::getExternalVn(const Varnode* loopVn)
{
    for (auto it: phiNodes)
    {
        if (loopVn->getOffset() == it->registerOffset)
            return it->varnodes[1];
    }
    return nullptr;
}

VectorLoopMatch::VectorLoopMatch(Funcdata& fData, PcodeOp* vsetOp) :
    data(fData),
    selectionStartAddr(0),
    selectionEndAddr(0),
    numPcodes(0),
    loopFound(false),
    loopStartAddr(0),
    loopEndAddr(0),
    phiNodes(),
    foundSimpleComparison(false),
    foundUnexpectedOp(false),
    foundOtherUserPcodes(false),
    simpleFlowStructure(true),
    simpleLoadStoreStructure(true),
    vectorRegistersMatch(false),
    numArithmeticOps(0),
    multiplier(1),
    elementSize(0),
    vsetOp(nullptr),
    vNumElem(nullptr),
    vNumPerLoop(nullptr),
    vLoadVn(nullptr),
    vLoadImmVn(nullptr),
    vStoreVn(nullptr),
    analysisEnabled(true)
{
    bool trace = loopLogger->should_log(spdlog::level::trace);
    bool info = loopLogger->should_log(spdlog::level::info);
    if (vsetOp == nullptr) return;
    loopLogger->trace("Analyzing potential vector loop at 0x{0:x}",
        vsetOp->getAddr().getOffset());
    // PcodeOps we believe to be part of this vector loop
    std::set<PcodeOp*> opsInLoop;
    // PcodeOps we believe to outside this vector loop and in need of dependency pruning
    std::set<PcodeOp*> opsExternalToLoop;
    // PcodeOps we want to visit on this iteration,
    std::set<PcodeOp*> visitPending;
    // PcodeOps we want to visit on the next iteration,
    std::set<PcodeOp*> candidates;
    // Schedule analysis of this vset pcodeop
    visitPending.insert(vsetOp);
    loopLogger->trace("Listing PcodeOpTree of vset trigger");
    // Add any PcodeOps found in this PcodeOpTree
    loopStartAddr = vsetOp->getAddr().getOffset();
    loopBlock = vsetOp->getParent();
    loopEndAddr = loopBlock->getStop().getOffset();
    const int MAX_SELECTION = 20;
    analysisEnabled = true;
    PcodeOpTree::const_iterator iter = data.beginOp(vsetOp->getAddr());
    PcodeOpTree::const_iterator enditer = data.endOp(vsetOp->getAddr());
    // This loop collects PcodeOps that share an instruction address
    // with the given vsetOp, then adds PcodeOps that descend (read outputs)
    // from any of those collected PcodeOps.
    while(iter!=enditer) {
        loopLogger->trace("  Iterating over vset phi pcodes, visitPending size = {0:d}",
            visitPending.size());
        // iter points at a (SeqNum, PcodeOp*) pair
        PcodeOp *op = (*iter).second;
        ++iter;
        //skip if we are already planning on visiting this pcodeop
        if (visitPending.find(op) != visitPending.end())
            continue;
        loopLogger->trace("  Tree op at 0x{0:x}:0x{1:x}",
            op->getAddr().getOffset(),
            op->getSeqNum().getTime());
        // add new pcodes to the visit pending set
        if (trace) displayPcodeOp(*op, "vset phi pcode added to Pending list", true);
        visitPending.insert(op);
    }
    loopLogger->trace("Finished iterating over vset phi pcodes, visitPending size = {0:d}",
        visitPending.size());
    std::set<PcodeOp*>::iterator it;
    static const int MAX_DEPTH = 5;
    // Iterate over visitPending to collect more PcodeOps
    for (int i=0; i < MAX_DEPTH; ++i)
    {
        if (visitPending.size() + opsInLoop.size() > MAX_SELECTION)
        {
            // too much complexity - fail the analysis
            analysisEnabled = false;
            loopLogger->warn("Loop analysis failed with {0:d} descendents",
                visitPending.size() + opsInLoop.size());
            pcodeOpSelection.clear();
            return;
        }
        loopLogger->trace("  Visiting {0:d} Pending nodes in iteration {1:d}", visitPending.size(),
            i);
        it = visitPending.begin();
        // iterate over pending visits, collecting possibly related PcodeOps candidates
        while (it != visitPending.end())
        {
            // add this pcodeop to ops we need to examine 
            intb opOffset = (*it)->getAddr().getOffset();
            if ((opOffset >= loopStartAddr) && (opOffset <= loopEndAddr))
                opsInLoop.insert(*it);
            else opsExternalToLoop.insert(*it);
            Varnode* outVn = (*it)->getOut();
            if (outVn != nullptr)
            {
                loopLogger->trace("    Scanning varnode 0x{0:x} for descendents", outVn->getAddr().getOffset());
                std::list<PcodeOp*>::const_iterator outVnEndIter = outVn->endDescend();
                for (std::list<PcodeOp*>::const_iterator itDesc=outVn->beginDescend();itDesc!=outVnEndIter;++itDesc)
                {
                    if ((opsInLoop.find(*itDesc) == opsInLoop.end()) &&
                        (opsExternalToLoop.find(*itDesc) == opsExternalToLoop.end()) &&
                        (visitPending.find(*itDesc) == visitPending.end()) &&
                        (candidates.find(*itDesc) == candidates.end()))
                    {
                        loopLogger->trace("    Adding a candidate PcodeOp at 0x{0:x}",
                            (*itDesc)->getAddr().getOffset());
                        if (trace) displayPcodeOp(**itDesc, "new descendent added to pending list", false);
                        candidates.insert(*itDesc);
                        loopLogger->trace("    Now have {0:d} candidates", candidates.size());
                    }
                }
            }
            ++it;
        }
        visitPending.clear();
        visitPending.insert(candidates.begin(), candidates.end());
        candidates.clear();
    }

    // Copy the set of opsInLoop PcodeOps into pcodeOpSelection, which
    // has a custom ordering relation to sort the list by Address and SeqNum
    it = opsInLoop.begin();
    while (it != opsInLoop.end())
    {
        pcodeOpSelection.insert(*it);
        ++it;
    }
    it = opsExternalToLoop.begin();
    while (it != opsExternalToLoop.end())
    {
        pcodeOpDependencies.insert(*it);
        ++it;
    }
    if (info) {
        loopLogger->info("Completed the descendent scan, finding {0:d} PcodeOps in Loop",
            pcodeOpSelection.size());
        loopLogger->info("    and {0:d} PcodeOp external dependencies",
                pcodeOpDependencies.size());
        it = pcodeOpSelection.begin();
        while (it != pcodeOpSelection.end())
        {
            displayPcodeOp(**it, "In Loop", false);
            ++it;
        }
        it = pcodeOpDependencies.begin();
        while (it != pcodeOpDependencies.end())
        {
            displayPcodeOp(**it, "Out of Loop", false);
            ++it;
        }
    }
}

VectorLoopMatch::~VectorLoopMatch()
{
    for (auto it: phiNodes)
    {
        delete it;
    }
}

void VectorLoopMatch::analyze()
{
    bool info = loopLogger->should_log(spdlog::level::info);
    numPcodes = pcodeOpSelection.size();
    PcodeOp* firstOp = *(pcodeOpSelection.begin());
    PcodeOp* lastOp = *(--pcodeOpSelection.end());
    selectionStartAddr = firstOp->getAddr().getOffset();
    selectionEndAddr = lastOp->getAddr().getOffset();
    foundOtherUserPcodes = false;
    foundSimpleComparison = false;
    foundUnexpectedOp = false;
    Varnode* vectorLoadRegisterVn = nullptr;
    Varnode* vectorStoreRegisterVn = nullptr;
    std::set<PcodeOp*, VectorLoopMatch::PcodeOpComparator>::iterator it = pcodeOpSelection.begin();
    bool analysisFailed = false;
    loopLogger->trace("Beginning vector loop analysis of {0:d} pcodes", pcodeOpSelection.size());
    while (it != pcodeOpSelection.end() && !analysisFailed)
    {
        PcodeOp* op = *it;
        ++it;
        intb opOffset = op->getAddr().getOffset();
        switch(op->code())
        {
          case CPUI_BRANCH:
            simpleFlowStructure = false;
            break;
          case CPUI_CBRANCH:
            {
                // Is this a backwards conditional branch to a target within the selection?
                intb branchTargetOffset = op->getIn(0)->getAddr().getOffset();
                loopFound = (branchTargetOffset >= selectionStartAddr) && (branchTargetOffset < opOffset);
            }
            break;
          case CPUI_BRANCHIND:
            simpleFlowStructure = false;
            break;
          case CPUI_CALL:
            simpleFlowStructure = false;
            analysisFailed = true;
            break;
          case CPUI_CALLOTHER:
            // Possible vector instruction
            {
                const RiscvUserPcode* opInfo = RiscvUserPcode::getUserPcode(*op);
                if (opInfo == nullptr)
                {
                    // may also be other builtin pcodes
                    foundOtherUserPcodes = true;
                }
                else if (opInfo->isVset)
                {
                    vsetOp = op;
                    multiplier = opInfo->multiplier;
                    elementSize = opInfo->elementSize;
                    vNumElem = op->getIn(1);
                    vNumPerLoop = op->getOut();
                    loopLogger->trace("Vset found: numElementsRegister=0x{0:x}",
                        vNumElem->getOffset());
                }
                else if ((opInfo->isLoad) && (vLoadVn == nullptr))
                {
                    const Varnode* vLoopLoadVn = op->getIn(1);
                    vLoadVn = getExternalVn(vLoopLoadVn);
                    vectorLoadRegisterVn = op->getOut();
                    loopLogger->trace("Vload found: register=0x{0:x}",
                        vectorLoadRegisterVn->getOffset());
                }
                else if ((opInfo->isLoadImmediate) && (vLoadImmVn == nullptr))
                {
                    vLoadImmVn = op->getIn(2);
                    loopLogger->trace("VloadImmediate found: numElem={0:d}", vLoadImmVn->getOffset());
                }
                else if ((opInfo->isStore) && (vStoreVn == nullptr))
                {
                    vectorStoreRegisterVn = op->getIn(1);
                    Varnode* vLoopStoreVn = op->getIn(2);
                    vStoreVn = getExternalVn(vLoopStoreVn);
                    loopLogger->trace("Vstore found: vector register=0x{0:x}; destination register=0x{1:x}",
                        vectorStoreRegisterVn->getOffset(), vLoopStoreVn->getOffset());
                }
                else foundOtherUserPcodes = true;
            }
            break;
          case CPUI_RETURN:
            simpleFlowStructure = false;
            break;
          case CPUI_INT_NOTEQUAL:
            foundSimpleComparison = true;
            break;
          case CPUI_INT_ADD:
            ++numArithmeticOps;
            break;
          case CPUI_INT_SUB:
            ++numArithmeticOps;
            break;
          case CPUI_PTRADD:
            ++numArithmeticOps;
            break;
          case CPUI_INT_MULT:
            // Probably a multiply by -1
            break;
          case CPUI_INT_2COMP:
            // Probably a multiply by -1
            break;
          case CPUI_MULTIEQUAL:
            {
                // first argument is generally a loop varnode, second is generally the external or input varnode,
                // an optional third argument may be a duplicate or unique.
                Varnode* a = op->getIn(0);
                Varnode* b = op->getIn(1);
                Varnode* c = nullptr;
                intb reg = op->getOut()->getOffset();
                if (op->numInput() == 3)
                {
                    c = op->getIn(2);
                }
                loopLogger->trace("Adding Phi node: register=0x{0:x}", reg);
                phiNodes.push_back(new PhiNode(reg, a, b, c));
            }
            break;
          case CPUI_CAST:
            // TODO
            break;
          default:
            {
                foundUnexpectedOp = true;
                displayPcodeOp(*op, "Unexpected op found in analysis", false);
                int opcode = op->code();
                loopLogger->warn("Unexpected op found in analysis: {0:d}", opcode);
            }
            break;
        }
    }
    vectorRegistersMatch = (vectorLoadRegisterVn == vectorStoreRegisterVn);
    vNumElem = getExternalVn(vNumElem);
    loopLogger->trace("vNumElem Varnode adjusted");
    if (info)
    {

        logFile << "Analysis of vector sequence beginning at 0x" << std::hex << selectionStartAddr << std::dec << std::endl;
        logFile << "\tnumPcodes = " << numPcodes <<  std::endl;
        logFile << "\telementSize = " << elementSize <<  std::endl;
        logFile << "\tmultiplier = " << multiplier <<  std::endl;
        logFile << "\tLength in Bytes = " << selectionEndAddr - selectionStartAddr <<  std::endl;
        logFile << "\tloopFound = " << loopFound <<  std::endl;
        logFile << "\tsimpleFlowStructure = " << simpleFlowStructure <<  std::endl;
        logFile << "\tsimpleLoadStoreStructure = " << simpleLoadStoreStructure << std::endl;
        logFile << "\tfoundOtherUserPcodes = " << foundOtherUserPcodes << std::endl;
        logFile << "\tfoundSimpleComparison = " << foundSimpleComparison << std::endl;
        logFile << "\tfoundUnexpectedOp = " << foundUnexpectedOp << std::endl;
        logFile << "\tnumArithmeticOps = " << numArithmeticOps << std::endl;
        logFile << "\tvectorRegistersMatch = " << vectorRegistersMatch << std::endl;
        displayPcodeOp(*vsetOp, "Vset operation:", false);
        if (vStoreVn != nullptr)
        {
            logFile << "Vstore parameter:" << std::endl;
            vStoreVn->printRaw(logFile);
            logFile << std::endl;
        }
        if (vLoadVn != nullptr)
        {
            logFile << "Vload parameter:" << std::endl;
            vLoadVn->printRaw(logFile);
            logFile << std::endl;
        }
        if (vNumElem != nullptr)
        {
            logFile << "VNumElem parameter:" << std::endl;
            vNumElem->printRaw(logFile);
            logFile << std::endl;
        }
    }
}
bool VectorLoopMatch::isMemcpy()
{
    return loopFound && (numPcodes > 10) && (numPcodes < 14) &&
        simpleFlowStructure && simpleLoadStoreStructure && foundSimpleComparison &&
        vectorRegistersMatch && (numArithmeticOps >=3) && (!foundUnexpectedOp);
}
int VectorLoopMatch::transform()
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
}