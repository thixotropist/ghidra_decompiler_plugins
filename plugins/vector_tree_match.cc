#include <string>
#include <set>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

#include "riscv.hh"
#include "vector_tree_match.hh"
#include "diagnostics.hh"
#include "utility.hh"

namespace ghidra
{
static void getPcodeOpTree(std::set<PcodeOp*>& pTree, const Funcdata& data, const PcodeOp* p)
{
    if (p == nullptr) return;
    Address addr = p->getAddr();
    PcodeOpTree::const_iterator iter = data.beginOp(addr);
    PcodeOpTree::const_iterator enditer = data.endOp(addr);
    while(iter!=enditer) {
        PcodeOp *op = (*iter).second;
        ++iter;
        pTree.insert(op);
    }
}

static void displayPcodeOpTree(Funcdata& data, const PcodeOp* p)
{
    if (p == nullptr) return;
    Address addr = p->getAddr();
    PcodeOpTree::const_iterator iter = data.beginOp(addr);
    PcodeOpTree::const_iterator enditer = data.endOp(addr);
    displayComment("Listing PcodeOpTree");
    while(iter!=enditer) {
        PcodeOp *op = (*iter).second;
        ++iter;
        displayPcodeOp(*op, "", false);
    }
}

/**
 * @brief merge treeOps into candidates unless they already exist
 * within visited or visitPending
 * 
 * @param resultSet The result of this set union 
 * @param inputSet The set to be merged if not an element of an exclude set 
 * @param excludeSet1 First of two exclusion sets
 * @param excludeSet2 Second of two exclusion sets
 */
static void mergeUniquePcodeOps(
    std::set<PcodeOp*>& resultSet,
    const std::set<PcodeOp*>& inputSet,
    const std::set<PcodeOp*>& excludeSet1,
    const std::set<PcodeOp*>& excludeSet2
    )
{
    for (std::set<PcodeOp *>::const_iterator it = inputSet.begin();
         it != inputSet.end();
         ++it)
    {
        if ((excludeSet1.find(*it) == excludeSet1.end()) &&
            (excludeSet2.find(*it) == excludeSet2.end()))
        {
            resultSet.insert(*it);
        }
    }
}

Varnode* VectorTreeMatch::getExternalVn(const Varnode* loopVn)
{
    for (auto it: phiNodes)
    {
        if (loopVn->getOffset() == it->registerOffset)
            return it->externalVarnode;
    }
    return nullptr;
}

VectorTreeMatch::VectorTreeMatch(Funcdata& fData, PcodeOp* vsetOp) :
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
    vStoreVn(nullptr)
{
    bool trace = logger->should_log(spdlog::level::trace);
    bool info = logger->should_log(spdlog::level::info);
    if (vsetOp == nullptr) return;
    // PcodeOps we believe to be part of this vector loop
    std::set<PcodeOp*> visited;
    // PcodeOps we want to visit on this iteration,
    std::set<PcodeOp*> visitPending;
    // PcodeOps we want to visit on the next iteration,
    std::set<PcodeOp*> candidates;
    // Schedule analysis of this vset pcodeop
    visitPending.insert(vsetOp);
    if (trace) displayComment("Listing PcodeOpTree of vset trigger");
    // Add any PcodeOps found in this PcodeOpTree
    Address addr = vsetOp->getAddr();
    PcodeOpTree::const_iterator iter = data.beginOp(addr);
    PcodeOpTree::const_iterator enditer = data.endOp(addr);
    // This loop collects PcodeOps that share an instruction address
    // with the given vsetOp, then adds PcodeOps that descend (read outputs)
    // from any of those collected PcodeOps.
    while(iter!=enditer) {
        // iter points at a (SeqNum, PcodeOp*) pair
        PcodeOp *op = (*iter).second;
        ++iter;
        if (trace) displayPcodeOp(*op, "vset tree peers added to Pending list", true);
        // add the pcode to the visit pending set if not already visited
        if (visited.find(op) == visited.end()) visitPending.insert(op);
        // get the output varnode, if any.
        Varnode* v = op->getOut();
        if (v != nullptr)
        {
            // iterate over the descendents of this Varnode to see if a visit should be
            // scheduled.
            std::list<PcodeOp*>::const_iterator vnEnditer = v->endDescend();
            for (std::list<PcodeOp*>::const_iterator it=v->beginDescend();it!=vnEnditer;++it)
            {
                if (trace) displayPcodeOp(*op, "vset tree peer descendent added to Pending list", true);
                if (visited.find(*it) == visited.end()) visitPending.insert(*it);
            }
        }
    }
    if (trace) displayComment("Visiting Pending nodes");
    std::set<PcodeOp*>::iterator it;
    static const int MAX_DEPTH = 5;
    // Iterate over visitPending to collect more PcodeOps
    for (int i=0; i < MAX_DEPTH; ++i)
    {
        it = visitPending.begin();
        // iterate over pending visits, collecting possibly related PcodeOps candidates
        while (it != visitPending.end())
        {
            Varnode* outVn = (*it)->getOut();
            if (outVn != nullptr)
            {
                std::list<PcodeOp*>::const_iterator outVnEndIter = outVn->endDescend();
                for (std::list<PcodeOp*>::const_iterator itDesc=outVn->beginDescend();itDesc!=outVnEndIter;++itDesc)
                {
                    if (trace) {
                        logFile << "\t\t";
                        (*itDesc)->printRaw(logFile);
                        logFile << std::endl;
                    }
                    if ((visited.find(*itDesc) == visited.end()) &&
                        (visitPending.find(*itDesc) == visitPending.end()))
                    {
                        if (trace) displayPcodeOp(**itDesc, "new descendent added to pending list", false);
                        candidates.insert(*itDesc);
                    }
                    if (trace) displayPcodeOpTree(data, *itDesc);
                    std::set<PcodeOp*> treeOps;
                    getPcodeOpTree(treeOps, data, *itDesc);
                    mergeUniquePcodeOps(candidates, treeOps, visited, visitPending);
                }
            }
            ++it;
        }
        visited.insert(visitPending.begin(), visitPending.end());
        visitPending.clear();
        visitPending.insert(candidates.begin(), candidates.end());
        candidates.clear();
    }
    // Copy the set of visited PcodeOps into pcodeOpSelection, which
    // has a custom ordering relation to sort the list by Address and SeqNum
    it = visited.begin();
    while (it != visited.end())
    {
        pcodeOpSelection.insert(*it);
        ++it;
    }
    if (info) {
        displayComment("Completed the descendent scan, finding these PcodeOps");
        it = pcodeOpSelection.begin();
        while (it != pcodeOpSelection.end())
        {
            displayPcodeOp(**it, "", false);
            ++it;
        }
    }
}

VectorTreeMatch::~VectorTreeMatch()
{
    for (auto it: phiNodes)
    {
        delete it;
    }
}

void VectorTreeMatch::analyze()
{
    bool info = logger->should_log(spdlog::level::info);
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
    std::set<PcodeOp*, VectorTreeMatch::PcodeOpComparator>::iterator it = pcodeOpSelection.begin();
    while (it != pcodeOpSelection.end())
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
                    logger->trace("Vset found: numElementsRegister=0x{0:x}",
                        vNumElem->getOffset());
                }
                else if ((opInfo->isLoad) && (vLoadVn == nullptr))
                {
                    const Varnode* vLoopLoadVn = op->getIn(1);
                    vLoadVn = getExternalVn(vLoopLoadVn);
                    vectorLoadRegisterVn = op->getOut();
                    logger->trace("Vload found: register=0x{0:x}",
                        vectorLoadRegisterVn->getOffset());
                }
                else if ((opInfo->isLoadImmediate) && (vLoadImmVn == nullptr))
                {
                    vLoadImmVn = op->getIn(2);
                    logger->trace("VloadImmediate found: numElem={0:d}", vLoadImmVn->getOffset());
                }
                else if ((opInfo->isStore) && (vStoreVn == nullptr))
                {
                    vectorStoreRegisterVn = op->getIn(1);
                    Varnode* vLoopStoreVn = op->getIn(2);
                    vStoreVn = getExternalVn(vLoopStoreVn);
                    logger->trace("Vstore found: vector register=0x{0:x}; destination register=0x{1:x}",
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
          case CPUI_INT_MULT:
            // Probably a multiply by -1
            break;
          case CPUI_INT_2COMP:
            // Probably a multiply by -1
            break;
          case CPUI_MULTIEQUAL:
            {
                // first argument is generally a loop varnode, second is generally the external or input varnode
                Varnode* a = op->getIn(0);
                Varnode* b = op->getIn(1);
                intb reg = op->getOut()->getOffset();
                intb aReg = a->getOffset();
                intb bReg = b->getOffset();
                // all three reg values should be equal
                bool isRelevant = (reg == aReg) && (aReg == bReg);
                bool bIsInput = b->getFlags() & Varnode::input;
                intb aAddress = a->getAddr().getOffset();
                if (isRelevant && bIsInput)
                {
                    logger->trace("Adding Phi node: register=0x{0:x}; a=0x{1:x}; b=input",
                        reg, aAddress);
                    phiNodes.push_back(new PhiNode(reg, b, a));
                }
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
                logger->warn("Unexpected op found in analysis: {0:d}", opcode);
            }
            break;
        }
    }
    vectorRegistersMatch = (vectorLoadRegisterVn == vectorStoreRegisterVn);
    vNumElem = getExternalVn(vNumElem);
    logger->trace("vNumElem Varnode adjusted");
    if (info)
    {
        logFile << "Analysis:" << std::endl;
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
bool VectorTreeMatch::isMemcpy()
{
    return loopFound && (numPcodes > 10) && (numPcodes < 14) &&
        simpleFlowStructure && simpleLoadStoreStructure && foundSimpleComparison &&
        vectorRegistersMatch && (numArithmeticOps >=3) && (!foundUnexpectedOp);
}
int VectorTreeMatch::transform()
{
    logger->info("Transforming selection into builtin_memcpy");
    // todo: compute number of bytes to move, generate a new varnode
    PcodeOp* newOp = insertBuiltin(data, *vsetOp, UserPcodeOp::BUILTIN_MEMCPY, vStoreVn, vLoadVn, vNumElem);
    data.opInsertBefore(newOp, vsetOp);

    for (auto it: pcodeOpSelection)
    {
        data.opUnlink(it);
    }
    return 1;
}
}