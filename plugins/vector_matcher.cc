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
#include "utility.hh"

namespace ghidra
{


// recurse through the function's graph to replace all references to old with new.
//TODO: move this into a patch to the BlockGraph class
static void replaceBlock(const BlockGraph& sblocks, FlowBlock* oldBlock, FlowBlock* newBlock)
{
    riscvVectorLogger->trace("Entering replaceBlock");
    if (sblocks.getType() == FlowBlock::t_plain) return;

    vector<FlowBlock*>& list = const_cast<vector<FlowBlock*>&>(sblocks.getList());
    for(auto iter=list.begin();iter!=list.end();++iter)
    {
        if ((*iter)->getType() == FlowBlock::t_plain) continue;
        if ((*iter)->getType() == FlowBlock::t_copy) continue;
        BlockGraph* bg = reinterpret_cast<BlockGraph*>(*iter);
        if (*iter == oldBlock)
        {
            riscvVectorLogger->trace("\tReplacing oldBlock reference in BlockGraph index {0:d}",
                bg->getIndex());
            *iter = newBlock;
        }
        if ((*iter)->getType() == FlowBlock::t_if)
        {
            BlockIf* blkIf = reinterpret_cast<BlockIf*>(bg);
            riscvVectorLogger->trace("\tChecking BlockIf index {0:d}",
                blkIf->getIndex());
            if (blkIf->getGotoTarget() == oldBlock)
            {
                riscvVectorLogger->trace("\tReplacing oldBlock reference in BlockIf");
                blkIf->setGotoTarget(newBlock);
            }
        }
        if ((*iter)->getType() == FlowBlock::t_goto)
        {
            BlockGoto* blkGt = reinterpret_cast<BlockGoto*>(bg);
            riscvVectorLogger->trace("\tChecking BlockGoto index {0:d}",
                blkGt->getIndex());
            if (blkGt->getGotoTarget() == oldBlock)
            {
                riscvVectorLogger->trace("\tReplacing oldBlock reference in a new BlockGoto");
                blkGt->setGotoTarget(newBlock);
            }
        }
       replaceBlock(*bg, oldBlock, newBlock);
    }
}

VectorMatcher::VectorMatcher(Funcdata& fData, PcodeOp* initialVsetOp) :
    inspector(riscvVectorLogger),
    data(fData),
    codeSpace(nullptr),
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
    vLoad(nullptr),
    vLoadImm(nullptr),
    vStore(nullptr),
    trace(riscvVectorLogger->should_log(spdlog::level::trace)),
    info(riscvVectorLogger->should_log(spdlog::level::info))
{
    if (vsetOp == nullptr) return;
    // get basic info on the vsetop trigger
    const RiscvUserPcode* vsetInfo = RiscvUserPcode::getUserPcode(*vsetOp);
    numElementsConstant = vsetInfo->isVseti;
    numElementsVariable = vsetInfo->isVset;
    // we only want to trigger on two classes of vector ops
    if (!(vsetInfo->isVseti || vsetInfo->isVset)) return;
    multiplier = vsetInfo->multiplier;
    elementSize = vsetInfo->elementSize;
    if (vsetOp->numInput() < 2)
    {
        riscvVectorLogger->warn("Found a vsetOp at 0x{0:x}:{1:x} with no Varnodes",
            vsetOp->getAddr().getOffset(), vsetOp->getTime());
        return;
    }
    vNumElem = vsetOp->getIn(1);
    // determine if we have a loop and if so, where does it start and stop
    collect_control_flow_data();
    // terminate construction if this vset op doesn't start a loop
    if (!loopFound) return;
    riscvVectorLogger->info("Analyzing potential vector stanza at 0x{0:x}",
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
    riscvVectorLogger->info("Summary of traits:\n"
        "\tVector stanza begins at 0x{0:x}\n"
        "\telementSize = {1:d}\n"
        "\tmultiplier = {2:d}\n"
        "\tcode size = 0x{3:x}",
        loopStartAddr, elementSize, multiplier, loopEndAddr - loopStartAddr);
    riscvVectorLogger->info("\n"
        "\tNumber of Phi nodes affected by loop = {0:d}\n"
        "\tNumber of other UserPcodes = {1:d}\n"
        "\tNumber of arithmetic ops = {2:d}",
        phiNodesAffectedByLoop.size(), otherUserPcodes.size(), numArithmeticOps);
    riscvVectorLogger->info("\n"
        "\tNumber of elements is constant = {0:s}\n"
        "\tNumber of elements is variable = {1:s}\n"
        "\tFound simple comparison = {2:s}\n"
        "\tFound unexpected opcode = {3:s}",
        numElementsConstant ? "true" : "false",
        numElementsVariable ? "true" : "false",
        foundSimpleComparison ? "true" : "false",
        foundUnexpectedOp ? "true" : "false");
    riscvVectorLogger->info("\n"
        "\tFound other user  opcode = {0:s}\n"
        "\tFound simple flow structure = {1:s}\n"
        "\tFound simple load/store pattern = {2:s}\n"
        "\tFound vector registers match = {3:s}",
        foundOtherUserPcodes ? "true" : "false",
        simpleFlowStructure ? "true" : "false",
        simpleLoadStoreStructure ? "true" : "false",
        vectorRegistersMatch ? "true" : "false");
    riscvVectorLogger->info("\n"
        "\tNumber of elements varnode identified = {0:s}\n"
        "\tNumber of elements per loop varnode identified = {1:s}\n"
        "\tVector load address varnode identified = {2:s}\n"
        "\tVector store address varnode identified = {3:s}",
        vNumElem != nullptr ? "true" : "false",
        vNumPerLoop != nullptr ? "true" : "false",
        vLoad != nullptr ? "true" : "false",
        vStore != nullptr ? "true" : "false");
}

VectorMatcher::~VectorMatcher()
{
    externalDependentOps.clear();
}

bool VectorMatcher::isMemcpy()
{
    bool match = simpleFlowStructure && simpleLoadStoreStructure && foundSimpleComparison &&
        vectorRegistersMatch && (numArithmeticOps >=3) && (!foundUnexpectedOp) &&
        (!foundOtherUserPcodes);
    if (!match) return false;
    return true;
}

bool VectorMatcher::isDefinedInLoop(const Varnode* vn)
{
    const PcodeOp* definingOp = vn->getDef();
    if (definingOp == nullptr) return false; 
    intb offset = definingOp->getAddr().getOffset();
    bool addressInLoop = (offset >= loopStartAddr) && (offset <= loopEndAddr);
    bool blockIsLoopblock = definingOp->getParent() == loopBlock;
    return addressInLoop && blockIsLoopblock;
}

void VectorMatcher::reducePhiNode(PcodeOp* op)
{
    for (int slot = 0; slot < op->numInput(); ++slot)
    {
        const Varnode* baseVn = op->getIn(slot);
        for (int otherSlot = slot + 1; otherSlot < op->numInput(); ++otherSlot)
        {
            if (baseVn == op->getIn(otherSlot))
            {
                riscvVectorLogger->info("Removing duplicate Phi varnode at 0x{0:x}:{1:x}, slot = {2:d}",
                    op->getAddr().getOffset(), op->getTime(), otherSlot);
                data.opRemoveInput(op, otherSlot);
                if (info)
                {
                    std::stringstream ss;
                    op->printRaw(ss);
                    riscvVectorLogger->info("\tNew Phi PcodeOp is: {0:s}", ss.str());
                }
                --otherSlot;
            }
        }
    }
}

bool VectorMatcher::removeExteriorDependencies()
{
    if (externalDependentOps.empty())
        return true;
    // if the dependencies are simple Phi node terms, allow proceeding
    bool enableTransform = true;
    for (auto it: externalDependentOps)
    {
        bool isPhi = it->code() == CPUI_MULTIEQUAL;
        enableTransform &= isPhi;
        if (!isPhi)
            riscvVectorLogger->info("Unable to remove external dependency to non-Phi node 0x{0:x}:{1:x}",
                it->getAddr().getOffset(), it->getTime());
    }
    if (!enableTransform) return false;
    for (auto it: externalDependentOps)
    {
        PcodeOp* op = it;
        for (int slot = 0; slot < op->numInput(); ++slot)
        {
            if (isDefinedInLoop(op->getIn(slot)))
            {
                riscvVectorLogger->info("Removing exterior dependency at 0x{0:x}:{1:x}",
                    op->getAddr().getOffset(), op->getTime());
                data.opRemoveInput(op, slot);
                --slot;
            }
        }
    }
    return true;
}

void VectorMatcher::collect_control_flow_data()
{
    loopStartAddr = vsetOp->getAddr().getOffset();
    codeSpace = vsetOp->getAddr().getSpace();
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
    const FlowBlock* nextBlock = loopBlock->nextInFlow();
    const bool SHOW_NEXT_BLOCK = false;
    if (nextBlock != nullptr)
    {
        nextInstructionAddress = nextBlock->getStart();
        if (SHOW_NEXT_BLOCK && trace)
        {
        std::stringstream ss;
        nextBlock->printRaw(ss);
        riscvVectorLogger->trace("The next block identifies as: {0:s}\n\tNext instruction address is 0x:{1:x}",
            ss.str(), nextInstructionAddress.getOffset());
        }
    }
    else nextInstructionAddress=Address();
    if (loopFound)
    {
        riscvVectorLogger->info("Loop instruction range: 0x{0:x} to 0x{1:x} within AddrSpace {2:s}",
            loopStartAddr, loopEndAddr, codeSpace->getName());
        riscvVectorLogger->info("loopFound = {0:d}; simpleFlowStructure = {1:d}; "
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
    riscvVectorLogger->trace("  Iterating over vset phi pcodes");
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
                riscvVectorLogger->trace("  Analysis of Phi node: {0:s}",
                    ss.str());
            }
            int numArgs = op->numInput();
            for (int slot = 0; slot < numArgs; ++slot)
            {
                // where does this arg get written?
                if (trace)
                {
                    std::stringstream ss;
                    op->getIn(slot)->printRaw(ss);
                    riscvVectorLogger->trace("  Analysis of Varnode in slot {0:d}: {1:s}",
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
    riscvVectorLogger->trace("  Found {0:d} Phi nodes affected by the loop", phiNodesAffectedByLoop.size());
}

void VectorMatcher::examine_loop_pcodeops()
{
    std::list<PcodeOp*>::iterator it = loopBlock->beginOp();
    std::list<PcodeOp*>::iterator lastOp = loopBlock->endOp();
    bool analysisFailed = false;
    int conditional_branches = 0;
    riscvVectorLogger->trace("Beginning loop pcode analysis");
    while (it != lastOp && !analysisFailed)
    {
        PcodeOp* op = *it;
        ++it;
        intb opOffset = op->getAddr().getOffset();
        if (trace)
        {
            std::stringstream ss;
            op->printRaw(ss);
            riscvVectorLogger->trace("  PcodeOp at 0x{0:x}: {1:s}",
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
                else if ((opInfo->isLoadImmediate) && (vLoadImm == nullptr))
                {
                    // TODO: vector load immediate instructions should not be found inside a loop
                    vLoadImm = op->getIn(1);
                    riscvVectorLogger->trace("    VloadImmediate found: numElem={0:d}", vLoadImm->getOffset());
                }
                else if (opInfo->isVset || opInfo->isLoad || opInfo->isStore)
                    break;
                else
                {
                    foundOtherUserPcodes = true;
                    otherUserPcodes.push_back(op);
                    std::stringstream ss;
                    op->printRaw(ss);
                    riscvVectorLogger->trace("    Unexpected user pcode found at 0x{0:x}: {1:s}",
                        opOffset, ss.str());
                }
            }
            break;
          default:
            {
                foundUnexpectedOp = true;
                int opcode = op->code();
                riscvVectorLogger->warn("    Unexpected op found in analysis: {0:d}", opcode);
            }
        }
    }
}

void VectorMatcher::collect_loop_registers()
{
    // use lists instead of vectors to allow for push_back inside iterative loops
    std::list<Varnode *> dependentVarnodesInLoop;
    std::list<Varnode *> dependentVarnodesOutsideLoop;
    std::list<PcodeOp *> opsToVisit(phiNodesAffectedByLoop.begin(), phiNodesAffectedByLoop.end());
    Varnode* vLoopStoreVn = nullptr;
    Varnode* vectorNumElemVn = nullptr;
    Varnode* vectorLoadRegisterVn = nullptr;
    Varnode* vectorLoadAddrVn = nullptr;
    Varnode* vectorStoreRegisterVn = nullptr;
    Varnode* vectorStoreAddrVn = nullptr;
    std::stringstream ss;
    // For all Phi nodes affected by the loop determine the output register and its dependencies.
    for (auto op : opsToVisit)
    {
        if (trace)
        {
            op->printRaw(ss);
            riscvVectorLogger->trace("Examining context of: {0:s}", ss.str());
            ss.str("");
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
                riscvVectorLogger->info("Tracing loop dependencies for register result {0:s} with register offset 0x{1:x}",
                                 regName, resultVn->getAddr().getOffset());
            }
            else
            {
                riscvVectorLogger->info("Tracing loop dependencies for non-register object with offset 0x{0:x}",
                                 resultVn->getAddr().getOffset());
            }
        }
        if (isInsideLoop)
        {
            riscvVectorLogger->trace("  Examining context of op inside the loop:");
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
                    if (vNumPerLoop == nullptr)
                    {
                        riscvVectorLogger->warn("Vector vset found with no output register at 0x{0:x}",
                            op->getAddr().getOffset());
                        continue;
                    }
                    riscvVectorLogger->trace("    Vset found: numElementsRegister=0x{0:x}",
                                      vectorNumElemVn->getOffset());
                }
                else if (opInfo->isLoad)
                {
                    vectorLoadRegisterVn = op->getOut();
                    if (vectorLoadRegisterVn == nullptr)
                    {
                        riscvVectorLogger->warn("Vector load found with no output register at 0x{0:x}",
                            op->getAddr().getOffset());
                        continue;
                    }
                    vectorLoadAddrVn = op->getIn(1);
                    riscvVectorLogger->trace("    Vload found at 0x{0:x}", op->getAddr().getOffset());
                    riscvVectorLogger->flush();
                    riscvVectorLogger->trace("    Vload register=0x{0:x}",
                                      vectorLoadRegisterVn->getOffset());
                }
                else if (opInfo->isStore)
                {
                    riscvVectorLogger->flush();
                    vectorStoreRegisterVn = op->getIn(1);
                    vectorStoreAddrVn = op->getIn(2);
                    vLoopStoreVn = op->getIn(2);
                    riscvVectorLogger->trace("    Vstore found: vector register=0x{0:x}; destination register=0x{1:x}",
                                      vectorStoreRegisterVn->getOffset(), vLoopStoreVn->getOffset());
                }
            }
            if (info && (resultVn != nullptr))
            {
                resultVn->printRaw(ss);
                riscvVectorLogger->trace("  inloop dependency: {0:s}", ss.str());
                ss.str("");
            }
            if (opIsVoid) continue;
            // Add new dependent ops to visit if this op has a known result *and* this op is inside the loop
            list<PcodeOp *>::const_iterator begin = resultVn->beginDescend();
            list<PcodeOp *>::const_iterator end = resultVn->endDescend();
            for (auto descendent = begin; descendent != end; ++descendent)
            {
                PcodeOp *descendentOp = *descendent;
                if (trace)
                {
                    descendentOp->printRaw(ss);
                    riscvVectorLogger->trace("  Descendent op: {0:s}", ss.str());
                    ss.str("");
                }
                dependentVarnodesInLoop.push_back(resultVn);
                if (std::find(opsToVisit.begin(), opsToVisit.end(), descendentOp) == opsToVisit.end())
                    opsToVisit.push_back(descendentOp);
            }
        }
        else
        {
            riscvVectorLogger->trace("  Examining context of op outside the loop:");
            dependentVarnodesOutsideLoop.push_back(resultVn);
            if (std::find(externalDependentOps.begin(), externalDependentOps.end(), op) == externalDependentOps.end())
                externalDependentOps.push_back(op);
            if ((resultVn != nullptr) && info)
            {
                resultVn->printRaw(ss);
                riscvVectorLogger->trace("  exterior dependency to fix: {0:s}", ss.str());
                ss.str("");
            }
        }
    }
    // do load and store registers match?
    vectorRegistersMatch = (vectorLoadRegisterVn == vectorStoreRegisterVn);
    // find the Phi node defining the loop registers
    for (auto op: phiNodesAffectedByLoop)
    {
        if (trace)
        {
            op->printRaw(ss);
            riscvVectorLogger->trace("Checking PcodeOp for dependencies: {0:s}", ss.str());
            riscvVectorLogger->flush();
            ss.str("");
        }
        intb regOffset = op->getOut()->getAddr().getOffset();
        string regName;
        getRegisterName(op->getOut(), &regName);
        riscvVectorLogger->trace("Searching for loop variables referring to register {0:s}",
            regName);
        if ((vectorNumElemVn != nullptr) && (!vectorNumElemVn->isConstant()) && (regOffset == vectorNumElemVn->getOffset()))
        {
            if (trace)
            {
                op->getOut()->printRaw(ss);
                riscvVectorLogger->trace("\tvNumElem identified as {0:s}", ss.str());
                ss.str("");
            }
            vNumElem = op->getOut();
        }
        else if ((vectorLoadAddrVn != nullptr) && (regOffset == vectorLoadAddrVn->getOffset()))
        {
            if (trace)
            {
                op->getOut()->printRaw(ss);
                riscvVectorLogger->trace("\tvLoadVn identified as {0:s}", ss.str());
                ss.str("");
            }
            vLoad = op->getOut();
        }
        else if ((vectorStoreAddrVn != nullptr) && regOffset == vectorStoreAddrVn->getOffset())
        {
            if (trace)
            {
                op->getOut()->printRaw(ss);
                riscvVectorLogger->trace("\tvStoreVn identified as {0:s}", ss.str());
                ss.str("");
            }
            vStore = op->getOut();
        }
    }
}

void VectorMatcher::removeDoWhileWrapperBlock(BlockBasic* blk)
{
    FlowBlock* parentBlock = nullptr;
    FlowBlock* grandparentBlock = nullptr;
    riscvVectorLogger->info("Searching for an enclosing DoWhile block");
    FlowBlock* copyBlk = blk->getCopyMap();
    if (copyBlk == nullptr)
        riscvVectorLogger->trace("\tblk->getCopyMap() returns null");
    else
    {
        parentBlock = copyBlk->getParent();
        if (parentBlock == nullptr)
            riscvVectorLogger->trace("\tcopyBlk->getParent() returns null");
        else
        {
            std::stringstream ss;
            parentBlock->printRaw(ss);
            riscvVectorLogger->trace("Found candidate Parent block:\n{0:s}", ss.str());
            grandparentBlock = parentBlock->getParent();
            ss.str("");
            if (grandparentBlock == nullptr)
                riscvVectorLogger->trace("\tparentBlock->getParent() returns null");
            else
            {
                grandparentBlock->printRaw(ss);
                riscvVectorLogger->trace("Found candidate Grandparent block:\n{0:s}", ss.str());
            }
        }
    }
    if (grandparentBlock == nullptr) riscvVectorLogger->trace("Found no grandparent block");
    else
    {
        if ((parentBlock->getType() == FlowBlock::t_dowhile) &&
            (grandparentBlock->getType() == FlowBlock::t_ls))
        {
            riscvVectorLogger->info("Removing pointless DoWhile block");
            BlockList* lsb = reinterpret_cast<BlockList*>(grandparentBlock);
            BlockGraph* doWhile = reinterpret_cast<BlockDoWhile*>(parentBlock);
            intb index = -1;
            const vector< FlowBlock * > & list = lsb->getList();
            for (intb i = 0; i < list.size(); i++)
            {
                riscvVectorLogger->trace("Checking list entry {0:d} of type {1:d}",
                    i, (int)(list[i]->getType()));
                if (list[i] == parentBlock)
                {
                    index = i;
                    break;
                }
            }
            if (index == -1)
            {
                riscvVectorLogger->error("Unable to locate DoWhile block in List Block");
            }
            else
            {
                // Removing loop edge from the vector block to itself, remembering that
                // removeEdge is a method of the BlockGraph parent common to each.
                // TODO: collect all doWhile inEdges and outEdges into two vectors,
                //       *before* we reparent the vector block, then install these as vector block
                //       edges *after* we reparent the vector block.
                std::vector<FlowBlock*> edgesIn;
                for (int i = 0; i < doWhile->sizeIn(); i++)
                {
                    FlowBlock* ib = doWhile->getIn(i);
                    edgesIn.push_back(ib);
                    lsb->removeEdge(ib, doWhile);
                }
                std::vector<FlowBlock*> edgesOut;
                for (int i = 0; i < doWhile->sizeOut(); i++)
                {
                    FlowBlock* ob = doWhile->getOut(i);
                    edgesOut.push_back(ob);
                    lsb->removeEdge(doWhile, ob);
                }
                riscvVectorLogger->info("Removing internal loop edge from vector block");
                doWhile->removeEdge(copyBlk, copyBlk);
                const BlockGraph& graph = data.getStructure();
                // cast away const until we can move this code into the BlockGraph or Funcdata structure
                const BlockGraph& sblocks = data.getStructure();
                std::stringstream ss;
                graph.printTree(ss, 1);
                riscvVectorLogger->trace("Full tree before block replacement:\n{0:s}", ss.str());
                ss.str("");
                copyBlk->setParent(grandparentBlock);
                replaceBlock(sblocks, parentBlock, copyBlk);
                doWhile->removeComponentLink(copyBlk);
                graph.printTree(ss, 1);
                riscvVectorLogger->trace("Full tree after block replacement:\n{0:s}", ss.str());
                ss.str("");
                // restore the edges extracted from the doWhile block
                for (auto b: edgesIn)
                {
                    lsb->addEdge(b, copyBlk);
                }
                for (auto b: edgesOut)
                {
                    lsb->addEdge(copyBlk, b);
                }
                delete doWhile;
                graph.printTree(ss, 1);
                riscvVectorLogger->trace("Full tree after dowhile deletion:\n{0:s}", ss.str());
            }
        }
    }
}

int VectorMatcher::transform()
{
    const bool EXPLORE_BLOCKS = false;
    const int TRANSFORM_COMPLETED = 1;
    const int TRANSFORM_ROLLED_BACK = 0;
    std::stringstream ss;
    BlockGraph& graph = data.getStructure();

    if (info)
    {
        loopBlock->printRaw(ss);
        riscvVectorLogger->info("Vector loop block before transforms is\n{0:s}", ss.str());
        ss.str("");
    }

    // attempt to remove exterior dependencies on the scratch registers employed
    // by the vector code
    if (!removeExteriorDependencies())
    {
        riscvVectorLogger->warn("Unable to safely remove register dependencies at 0x{0:x}:{1:x}",
            vsetOp->getAddr().getOffset(), vsetOp->getTime());
        return TRANSFORM_ROLLED_BACK;
    }
    if (trace)
    {
        vStore->printRaw(ss); ss << ";";
        vLoad->printRaw(ss); ss << ";";
        vNumElem->printRaw(ss);
        riscvVectorLogger->trace("vStore, vLoadVn, vNumElem = {0:s}", ss.str());
        ss.str("");
    }

    // visit all pcodeops in the loop block
    // * Phi nodes are edited to replace loop variable varnodes with duplicates
    // * the newVector op is unchanged
    // * other loop ops are removed
    std::list<PcodeOp*>::iterator it = loopBlock->beginOp();
    std::list<PcodeOp*>::iterator lastOp = loopBlock->endOp();
    Varnode* externalVload = nullptr;
    Varnode* externalVstore = nullptr;
    Varnode* externalVnumElem = nullptr;
    while (it != lastOp)
    {
        PcodeOp* op = *it;
        ++it;
        Varnode* vOut = op->getOut();
        riscvVectorLogger->info("Transforming PcodeOp at 0x{0:x}:{1:x}",
            op->getAddr().getOffset(), op->getTime());
        if (op->code() == CPUI_MULTIEQUAL)
        {
            riscvVectorLogger->trace("\tReducing the Phi or MULTIEQUAL node at this location");
            // if there are only two varnodes in this Phi node, and one is a loop variable,
            // delete the Phi node and take the non-loop varnode as a parameter
            reducePhiNode(op);
            // Try the simplest case first
            if ((op->numInput() == 2) && (vOut != nullptr))
            {
                riscvVectorLogger->trace("\tAbsorbing this PcodeOp");
                Varnode* v0 = op->getIn(0);
                Varnode* v1 = op->getIn(1);
                Varnode* vParam;
                if (isDefinedInLoop(v0))
                    vParam = v1;
                else if (isDefinedInLoop(v1))
                    vParam = v0;
                else
                {
                    riscvVectorLogger->warn("\tUnable to recognize Phi node parameters");
                    continue;
                }
                if (trace)
                {
                    vParam->printRaw(ss);
                    riscvVectorLogger->trace("\tvParam is {0:s}", ss.str());
                    ss.str("");
                    riscvVectorLogger->flush();
                }
                if (sameRegister(vOut, vStore))
                {
                    riscvVectorLogger->trace("\tAcquiring the vector store address varnode");
                    externalVstore = vParam;
                }
                else if (sameRegister(vOut, vLoad))
                {
                    riscvVectorLogger->trace("\tAcquiring the vector load address varnode");
                    externalVload = vParam;
                }
                else if (sameRegister(vOut, vNumElem))
                {
                    riscvVectorLogger->trace("\tAcquiring the vector number of elements varnode");
                    externalVnumElem = vParam;
                }
                riscvVectorLogger->trace("\tDeleting the PcodeOP (and all of its descendents)");
                riscvVectorLogger->flush();
                data.opUnlink(op);
            }
            else if ((op->numInput() >= 3) && (vOut != nullptr))
            {
                // We need to preserve this Phi node after removing the interior Vnode reference
                riscvVectorLogger->trace("\tRemoving interior Varnodes from thisPcodeOP");
                for (int slot=0; slot < op->numInput(); ++slot)
                {
                    if ((op->getIn(slot)->isFree()) || (isDefinedInLoop(op->getIn(slot))))
                    {
                        riscvVectorLogger->trace("\tRemoved interior varnode in slot {0:d}", slot);
                        riscvVectorLogger->flush();
                        data.opRemoveInput(op, slot);
                        --slot;
                    }
                }
                // Acquire loop parameter varnodes
                if (sameRegister(vOut, vStore))
                {
                    riscvVectorLogger->trace("\tAcquiring the vector store address varnode");
                    externalVstore = vOut;
                }
                else if (sameRegister(vOut, vLoad))
                {
                    riscvVectorLogger->trace("\tAcquiring the vector load address varnode");
                    externalVload = vOut;
                }
                else if (sameRegister(vOut, vNumElem))
                {
                    riscvVectorLogger->trace("\tAcquiring the vector number of elements varnode");
                    externalVnumElem = vOut;
                }
            }
        }
        else
        {
            riscvVectorLogger->trace("\tDeleting the op at 0x{0:x}:{1:x}",
                op->getAddr().getOffset(), op->getTime());
            data.opUnlink(op);
        }
    }
    vLoad = externalVload;
    vStore = externalVstore;
    vNumElem = externalVnumElem;

    if (trace)
    {
        loopBlock->printRaw(ss);
        riscvVectorLogger->trace("Vector loop block after reducing Phi nodes is\n{0:s}", ss.str());
        ss.str("");
    }

    riscvVectorLogger->info("Transforming selection into vector_memcpy, flushing log buffers");

    PcodeOp* newVectorOp = insertBuiltin(data, loopBlock->getStop(), VECTOR_MEMCPY, vStore, vLoad, vNumElem);
    if (trace)
    {
        newVectorOp->printRaw(ss);
        riscvVectorLogger->info("\tInserting a new vector operation\n\t\t{0:s}", ss.str());
        ss.str("");
    }
    data.opInsertEnd(newVectorOp, loopBlock);
    if (trace)
    {
        Datatype* p1Type = newVectorOp->getIn(1)->getType();
        riscvVectorLogger->trace("\tparam1 datatypeId=0x{0:x}, name={1:s}, displayName={2:s}",
            p1Type->getId(), p1Type->getName(), p1Type->getDisplayName());
        if (newVectorOp->getOut() != nullptr)
        {
            Datatype* resultType = newVectorOp->getOut()->getType();
            riscvVectorLogger->trace("\tresult datatypeId=0x{0:x}, name={1:s}, displayName={2:s}",
                resultType->getId(), resultType->getName(), resultType->getDisplayName());
        }
    }
    riscvVectorLogger->info("Preparing to edit the flow block graph to remove the loop edge");
    graph.removeEdge(loopBlock, loopBlock);
    riscvVectorLogger->flush();
    //TODO: the following currently segfaults in processing unstructured gotos
    removeDoWhileWrapperBlock(loopBlock);
    if (!nextInstructionAddress.isInvalid())
    {
        // if there is a following block add a goto to close the block and reach the next block
        // place the goto at the end of the current block to satisfy BlockBasic constraints
        Address gotoLocation(codeSpace, loopEndAddr);
        PcodeOp* gotoOp = insertBranchOp(data, gotoLocation, nextInstructionAddress);
        if (trace)
        {
            gotoOp->printRaw(ss);
            riscvVectorLogger->info("\tInserting a goto op to finish this block\n\t\t{0:s}", ss.str());
            ss.str("");
        }
        data.opInsertEnd(gotoOp, loopBlock);
    }
    riscvVectorLogger->flush();
    if (info)
    {
        inspector.log("copyBlk after replacement", loopBlock->getCopyMap());
        inspector.log("basic block after replacement", loopBlock);
    }

    // Optionally explore the BlockGraph around our loop to see if we can
    // merge the DOWHILE block into its neighbors.  Results so far suggest that
    // it is possible but complex - replacing the function's BlockGraph entirely rather
    // than a simple edge edit.  Perhaps we could apply these loop-processing rules
    // earlier, between the point blocks are identified and the DOWHILE block is created?
    if (EXPLORE_BLOCKS && trace)
    {
        graph.printTree(ss, 1);
        riscvVectorLogger->trace("Examining full function BlockGraph Tree form after transform:\n{0:s}", ss.str());
        ss.str("");
        loopBlock->printRaw(ss);
        riscvVectorLogger->trace("\tThe loop block identifies as:\n{0:s}", ss.str());
        ss.str("");
        riscvVectorLogger->trace("\t\tLoop block ins = {0:d}, outs = {1:d}", loopBlock->sizeIn(), loopBlock->sizeOut());
        int index = 0;
        FlowBlock* fb = loopBlock->subBlock(index);
        if (fb == nullptr)
            riscvVectorLogger->trace("\t\tloop block has no sub blocks");
        while (fb != nullptr)
        {
            fb->printRaw(ss);
            riscvVectorLogger->trace("\tInterior subblock {0:d} identifies as\n{0:s}", index, ss.str());
            index++;
            riscvVectorLogger->trace("\t\tBlock ins = {0:d}, outs = {1:d}", fb->sizeIn(), fb->sizeOut());
            fb = loopBlock->subBlock(index);
        }
        FlowBlock* parentBlock = loopBlock->getParent();
        parentBlock->printRaw(ss);
        riscvVectorLogger->trace("\tThe parent basic block to our loop block identifies as:\n{0:s}", ss.str());
        ss.str("");
        riscvVectorLogger->trace("\t\tParent block ins = {0:d}, outs = {1:d}", parentBlock->sizeIn(), parentBlock->sizeOut());
        // identify the output edge blocks
        for (index=0; index < loopBlock->sizeOut(); ++index)
        {
            fb = loopBlock->getOut(index);
            fb->printRaw(ss);
            riscvVectorLogger->trace("\t\tParent's output block {0:d} identifies as\n{1:s}", index, ss.str());
            ss.str("");
        }
        FlowBlock* dominator = loopBlock->getImmedDom();
        dominator->printRaw(ss);
        riscvVectorLogger->trace("\tThe immediate dominator block to our loop block identifies as:\n{0:s}", ss.str());
        ss.str("");
        riscvVectorLogger->trace("List of FlowBlocks in the function:");
        int i = 0;
        while (i < graph.getSize())
        {
            graph.subBlock(i)->printRaw(ss);
            riscvVectorLogger->trace("\t{0:s}", ss.str());
            ss.str("");
            i++;
        }
    }
    riscvVectorLogger->flush();
    return TRANSFORM_COMPLETED;
}
}
