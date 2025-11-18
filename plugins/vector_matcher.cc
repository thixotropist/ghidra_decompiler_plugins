#include <string>
#include <sstream>
#include <set>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"

#include "framework.hh"
#include "riscv.hh"
#include "vector_matcher.hh"
#include "vector_ops.hh"

namespace ghidra
{

VectorMatcher::VectorMatcher(Funcdata& fData, PcodeOp* initialVsetOp) :
    loopModel(fData, pLogger->should_log(spdlog::level::trace)),
    inspector(pLogger),
    data(fData),
    codeSpace(nullptr),
    numElementsConstant(false),
    numElementsVariable(false),
    vectorRegistersMatch(false),
    multiplier(1),
    elementSize(0),
    vsetOp(initialVsetOp),
    vNumElem(nullptr),
    vNumPerLoop(nullptr),
    vLoad(nullptr),
    vLoadImm(nullptr),
    vStore(nullptr),
    trace(pLogger->should_log(spdlog::level::trace)),
    info(pLogger->should_log(spdlog::level::info))
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
        pLogger->warn("Found a vsetOp at 0x{0:x}:{1:x} with no Varnodes",
            vsetOp->getAddr().getOffset(), vsetOp->getTime());
        return;
    }
    vNumElem = vsetOp->getIn(1);
    // determine if we have a loop and if so, where does it start and stop
    loopBlock = vsetOp->getParent();
    loopModel.analyze(vsetOp);
    // terminate construction if this vset op doesn't start a loop
    if (!loopModel.loopFound) return;
    // Follow dependencies of phi nodes within the loop to identify
    // source and destination pointer registers and the counter register
    collect_loop_registers();
    // show traits we have deduced
    pLogger->info("Summary of traits:\n"
        "\tVector stanza begins at 0x{0:x}\n"
        "\telementSize = {1:d}\n"
        "\tmultiplier = {2:d}\n"
        "\tcode size = 0x{3:x}",
        loopModel.firstAddr, elementSize, multiplier, loopModel.lastAddr - loopModel.firstAddr);
    pLogger->info("\n"
        "\tNumber of loop vector opcodes = {0:d}\n"
        "\tNumber of Phi nodes affected by loop = {1:d}\n"
        "\tNumber of arithmetic ops = {2:d}",
        loopModel.vectorOps.size(), loopModel.phiNodesAffectedByLoop.size(),
        loopModel.scalarOps.size());
    pLogger->info("\n"
        "\tNumber of elements is constant = {0:s}\n"
        "\tNumber of elements is variable = {1:s}\n"
        "\tFound unexpected Ghidra opcode = {2:s}\n"
        "\tFound unexpected vector opcode = {3:s}\n"
        "\tFound unexpected user pcodes = {4:s}",
        numElementsConstant ? "true" : "false",
        numElementsVariable ? "true" : "false",
        (loopModel.otherScalarOps.size() > 0) ? "true" : "false",
        (loopModel.otherVectorOps.size() > 0) ? "true" : "false",
        (loopModel.otherUserPcodes.size() > 0) ? "true" : "false"
    );
    pLogger->info("\tFound simple flow structure = {0:s}\n"
        "\tFound vector registers match = {1:s}",
        loopModel.simpleFlowStructure ? "true" : "false",
        vectorRegistersMatch ? "true" : "false");
    pLogger->info("\n"
        "\tNumber of elements varnode identified = {0:s}\n"
        "\tNumber of elements per loop varnode identified = {1:s}\n"
        "\tVector load address varnode identified = {2:s}\n"
        "\tVector store address varnode identified = {3:s}",
        vNumElem != nullptr ? "true" : "false",
        vNumPerLoop != nullptr ? "true" : "false",
        vLoad != nullptr ? "true" : "false",
        vStore != nullptr ? "true" : "false");
    // log the new VectorLoop results
    loopModel.log();
}

VectorMatcher::~VectorMatcher()
{
    externalDependentOps.clear();
}

bool VectorMatcher::isMemcpy()
{
    // apply generic tests first
    bool pre_match =
        (loopModel.loopFlags == 0x0) &&              // no flagged features
        loopModel.simpleFlowStructure &&             // no other  branches or calls
        (loopModel.vectorOps.size() == 3) &&         // vset, vload, vstore
        (loopModel.scalarOps.size() >= 5) &&         // expected pointer and counter arithmetic
        (loopModel.otherScalarOps.size() == 0) &&    // no other ghidra pcodeops
        (loopModel.otherVectorOps.size() == 0) &&    // no unhandled vector instructions
        (loopModel.otherUserPcodes.size() == 0);     // no other CALL_OTHER
    // add more complex tests specific to this pattern
    bool match = pre_match && vectorRegistersMatch;  // vector load and store use the same register
    return match;
}

bool VectorMatcher::isStrlen()
{
    // apply generic tests first
    bool pre_match =
        (loopModel.loopFlags == ghidra::RISCV_VEC_INSN_FAULT_ONLY_FIRST) && // vector fault only first load
        loopModel.simpleFlowStructure &&            // no other  branches or calls
        (loopModel.vectorOps.size() == 4) &&        // vset, vload, vseq, vfirst
        (loopModel.scalarOps.size() == 3) &&        // expected pointer and counter arithmetic
        (loopModel.otherScalarOps.size() == 0) &&   // no other ghidra pcodeops
        (loopModel.otherVectorOps.size() == 0) &&   // no unhandled vector instructions
        (loopModel.otherUserPcodes.size() == 0);    // no other CALL_OTHER
    bool match = pre_match;
    return match;
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
                pLogger->info("Removing duplicate Phi varnode at 0x{0:x}:{1:x}, slot = {2:d}",
                    op->getAddr().getOffset(), op->getTime(), otherSlot);
                data.opRemoveInput(op, otherSlot);
                if (info)
                {
                    std::stringstream ss;
                    op->printRaw(ss);
                    pLogger->info("\tNew Phi PcodeOp is: {0:s}", ss.str());
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
            pLogger->info("Unable to remove external dependency to non-Phi node 0x{0:x}:{1:x}",
                it->getAddr().getOffset(), it->getTime());
    }
    if (!enableTransform) return false;
    for (auto it: externalDependentOps)
    {
        PcodeOp* op = it;
        for (int slot = 0; slot < op->numInput(); ++slot)
        {
            if (loopModel.isDefinedInLoop(op->getIn(slot)))
            {
                pLogger->info("Removing exterior dependency at 0x{0:x}:{1:x}",
                    op->getAddr().getOffset(), op->getTime());
                data.opRemoveInput(op, slot);
                --slot;
            }
        }
    }
    return true;
}

void VectorMatcher::collect_loop_registers()
{
    // use lists instead of vectors to allow for push_back inside iterative loops
    std::list<Varnode *> dependentVarnodesInLoop;
    std::list<Varnode *> dependentVarnodesOutsideLoop;
    std::list<PcodeOp *> opsToVisit(loopModel.phiNodesAffectedByLoop.begin(), loopModel.phiNodesAffectedByLoop.end());
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
            pLogger->trace("Examining context of: {0:s}", ss.str());
            ss.str("");
        }
        Varnode *resultVn = op->getOut();
        // descendent ops with no return value need to be checked for content but not dependencies.
        bool opIsVoid = (resultVn == nullptr);
        intb offset = op->getAddr().getOffset();
        bool isInsideLoop = (offset >= loopModel.firstAddr) && (offset <= loopModel.lastAddr);
        if (info && !opIsVoid)
        {
            string regName;
            getRegisterName(resultVn, &regName);
            if (regName != "")
            {
                pLogger->info("Tracing loop dependencies for register result {0:s} with register offset 0x{1:x}",
                                 regName, resultVn->getAddr().getOffset());
            }
            else
            {
                pLogger->info("Tracing loop dependencies for non-register object with offset 0x{0:x}",
                                 resultVn->getAddr().getOffset());
            }
        }
        if (isInsideLoop)
        {
            pLogger->trace("  Examining context of op inside the loop:");
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
                        pLogger->warn("Vector vset found with no output register at 0x{0:x}",
                            op->getAddr().getOffset());
                        continue;
                    }
                    pLogger->trace("    Vset found: numElementsRegister=0x{0:x}",
                                      vectorNumElemVn->getOffset());
                }
                else if (opInfo->isLoad)
                {
                    vectorLoadRegisterVn = op->getOut();
                    if (vectorLoadRegisterVn == nullptr)
                    {
                        pLogger->warn("Vector load found with no output register at 0x{0:x}",
                            op->getAddr().getOffset());
                        continue;
                    }
                    vectorLoadAddrVn = op->getIn(1);
                    pLogger->trace("    Vload found at 0x{0:x}", op->getAddr().getOffset());
                    pLogger->flush();
                    pLogger->trace("    Vload register=0x{0:x}",
                                      vectorLoadRegisterVn->getOffset());
                }
                else if (opInfo->isStore)
                {
                    pLogger->flush();
                    vectorStoreRegisterVn = op->getIn(1);
                    vectorStoreAddrVn = op->getIn(2);
                    vLoopStoreVn = op->getIn(2);
                    pLogger->trace("    Vstore found: vector register=0x{0:x}; destination register=0x{1:x}",
                                      vectorStoreRegisterVn->getOffset(), vLoopStoreVn->getOffset());
                }
            }
            if (info && (resultVn != nullptr))
            {
                resultVn->printRaw(ss);
                pLogger->trace("  inloop dependency: {0:s}", ss.str());
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
                    pLogger->trace("  Descendent op: {0:s}", ss.str());
                    ss.str("");
                }
                dependentVarnodesInLoop.push_back(resultVn);
                if (std::find(opsToVisit.begin(), opsToVisit.end(), descendentOp) == opsToVisit.end())
                    opsToVisit.push_back(descendentOp);
            }
        }
        else
        {
            pLogger->trace("  Examining context of op outside the loop:");
            dependentVarnodesOutsideLoop.push_back(resultVn);
            if (std::find(externalDependentOps.begin(), externalDependentOps.end(), op) == externalDependentOps.end())
                externalDependentOps.push_back(op);
            if ((resultVn != nullptr) && info)
            {
                resultVn->printRaw(ss);
                pLogger->trace("  exterior dependency to fix: {0:s}", ss.str());
                ss.str("");
            }
        }
    }
    // do load and store registers match?
    vectorRegistersMatch = (vectorLoadRegisterVn == vectorStoreRegisterVn);
    // find the Phi node defining the loop registers
    for (auto op: loopModel.phiNodesAffectedByLoop)
    {
        if (trace)
        {
            op->printRaw(ss);
            pLogger->trace("Checking PcodeOp for dependencies: {0:s}", ss.str());
            pLogger->flush();
            ss.str("");
        }
        intb regOffset = op->getOut()->getAddr().getOffset();
        string regName;
        getRegisterName(op->getOut(), &regName);
        pLogger->trace("Searching for loop variables referring to register {0:s}",
            regName);
        if ((vectorNumElemVn != nullptr) && (!vectorNumElemVn->isConstant()) && (regOffset == vectorNumElemVn->getOffset()))
        {
            if (trace)
            {
                op->getOut()->printRaw(ss);
                pLogger->trace("\tvNumElem identified as {0:s}", ss.str());
                ss.str("");
            }
            vNumElem = op->getOut();
        }
        else if ((vectorLoadAddrVn != nullptr) && (regOffset == vectorLoadAddrVn->getOffset()))
        {
            if (trace)
            {
                op->getOut()->printRaw(ss);
                pLogger->trace("\tvLoadVn identified as {0:s}", ss.str());
                ss.str("");
            }
            vLoad = op->getOut();
        }
        else if ((vectorStoreAddrVn != nullptr) && regOffset == vectorStoreAddrVn->getOffset())
        {
            if (trace)
            {
                op->getOut()->printRaw(ss);
                pLogger->trace("\tvStoreVn identified as {0:s}", ss.str());
                ss.str("");
            }
            vStore = op->getOut();
        }
    }
}

int VectorMatcher::transformMemcpy()
{
    const bool EXPLORE_BLOCKS = false;
    std::stringstream ss;
    BlockGraph& graph = data.getStructure();

    if (info)
    {
        loopBlock->printRaw(ss);
        pLogger->info("Vector loop block before transforms is\n{0:s}", ss.str());
        ss.str("");
    }
    FunctionEditor functionEditor(data);
    // attempt to remove exterior dependencies on the scratch registers employed
    // by the vector code
    if (!removeExteriorDependencies())
    {
        pLogger->warn("Unable to safely remove register dependencies at 0x{0:x}:{1:x}",
            vsetOp->getAddr().getOffset(), vsetOp->getTime());
        return TRANSFORM_ROLLED_BACK;
    }
    if (trace)
    {
        vStore->printRaw(ss); ss << ";";
        vLoad->printRaw(ss); ss << ";";
        vNumElem->printRaw(ss);
        pLogger->trace("vStore, vLoadVn, vNumElem = {0:s}", ss.str());
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
        pLogger->info("Transforming PcodeOp at 0x{0:x}:{1:x}",
            op->getAddr().getOffset(), op->getTime());
        if (op->code() == CPUI_MULTIEQUAL)
        {
            pLogger->trace("\tReducing the Phi or MULTIEQUAL node at this location");
            // if there are only two varnodes in this Phi node, and one is a loop variable,
            // delete the Phi node and take the non-loop varnode as a parameter
            reducePhiNode(op);
            // Try the simplest case first
            if ((op->numInput() == 2) && (vOut != nullptr))
            {
                pLogger->trace("\tAbsorbing this PcodeOp");
                Varnode* v0 = op->getIn(0);
                Varnode* v1 = op->getIn(1);
                Varnode* vParam;
                if (loopModel.isDefinedInLoop(v0))
                    vParam = v1;
                else if (loopModel.isDefinedInLoop(v1))
                    vParam = v0;
                else
                {
                    pLogger->warn("\tUnable to recognize Phi node parameters");
                    continue;
                }
                if (trace)
                {
                    vParam->printRaw(ss);
                    pLogger->trace("\tvParam is {0:s}", ss.str());
                    ss.str("");
                    pLogger->flush();
                }
                if (sameRegister(vOut, vStore))
                {
                    pLogger->trace("\tAcquiring the vector store address varnode");
                    externalVstore = vParam;
                }
                else if (sameRegister(vOut, vLoad))
                {
                    pLogger->trace("\tAcquiring the vector load address varnode");
                    externalVload = vParam;
                }
                else if (sameRegister(vOut, vNumElem))
                {
                    pLogger->trace("\tAcquiring the vector number of elements varnode");
                    externalVnumElem = vParam;
                }
                pLogger->trace("\tDeleting the PcodeOP (and all of its descendents)");
                pLogger->flush();
                data.opUnlink(op);
            }
            else if ((op->numInput() >= 3) && (vOut != nullptr))
            {
                // We need to preserve this Phi node after removing the interior Vnode reference
                pLogger->trace("\tRemoving interior Varnodes from thisPcodeOP");
                for (int slot=0; slot < op->numInput(); ++slot)
                {
                    if ((op->getIn(slot)->isFree()) || (loopModel.isDefinedInLoop(op->getIn(slot))))
                    {
                        pLogger->trace("\tRemoved interior varnode in slot {0:d}", slot);
                        pLogger->flush();
                        data.opRemoveInput(op, slot);
                        --slot;
                    }
                }
                // Acquire loop parameter varnodes
                if (sameRegister(vOut, vStore))
                {
                    pLogger->trace("\tAcquiring the vector store address varnode");
                    externalVstore = vOut;
                }
                else if (sameRegister(vOut, vLoad))
                {
                    pLogger->trace("\tAcquiring the vector load address varnode");
                    externalVload = vOut;
                }
                else if (sameRegister(vOut, vNumElem))
                {
                    pLogger->trace("\tAcquiring the vector number of elements varnode");
                    externalVnumElem = vOut;
                }
            }
        }
        else
        {
            pLogger->trace("\tDeleting the op at 0x{0:x}:{1:x}",
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
        pLogger->trace("Vector loop block after reducing Phi nodes is\n{0:s}", ss.str());
        ss.str("");
    }

    pLogger->info("Transforming selection into vector_memcpy, flushing log buffers");

    PcodeOp* newVectorOp = insertVoidCallOther(data, loopBlock->getStop(), VECTOR_MEMCPY, vStore, vLoad, vNumElem);
    if (trace)
    {
        newVectorOp->printRaw(ss);
        pLogger->info("\tInserting a new vector operation\n\t\t{0:s}", ss.str());
        ss.str("");
    }
    data.opInsertEnd(newVectorOp, loopBlock);
    if (trace)
    {
        Datatype* p1Type = newVectorOp->getIn(1)->getType();
        pLogger->trace("\tparam1 datatypeId=0x{0:x}, name={1:s}, displayName={2:s}",
            p1Type->getId(), p1Type->getName(), p1Type->getDisplayName());
        if (newVectorOp->getOut() != nullptr)
        {
            Datatype* resultType = newVectorOp->getOut()->getType();
            pLogger->trace("\tresult datatypeId=0x{0:x}, name={1:s}, displayName={2:s}",
                resultType->getId(), resultType->getName(), resultType->getDisplayName());
        }
    }
    pLogger->info("Preparing to edit the flow block graph to remove the loop edge");
    graph.removeEdge(loopBlock, loopBlock);
    pLogger->flush();

    functionEditor.removeDoWhileWrapperBlock(loopBlock);
    if (!nextInstructionAddress.isInvalid())
    {
        // if there is a following block add a goto to close the block and reach the next block
        // place the goto at the end of the current block to satisfy BlockBasic constraints
        Address gotoLocation(codeSpace, loopModel.lastAddr);
        PcodeOp* gotoOp = insertBranchOp(data, gotoLocation, nextInstructionAddress);
        if (trace)
        {
            gotoOp->printRaw(ss);
            pLogger->info("\tInserting a goto op to finish this block\n\t\t{0:s}", ss.str());
            ss.str("");
        }
        data.opInsertEnd(gotoOp, loopBlock);
    }
    pLogger->flush();
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
        pLogger->trace("Examining full function BlockGraph Tree form after transform:\n{0:s}", ss.str());
        ss.str("");
        loopBlock->printRaw(ss);
        pLogger->trace("\tThe loop block identifies as:\n{0:s}", ss.str());
        ss.str("");
        pLogger->trace("\t\tLoop block ins = {0:d}, outs = {1:d}", loopBlock->sizeIn(), loopBlock->sizeOut());
        int index = 0;
        FlowBlock* fb = loopBlock->subBlock(index);
        if (fb == nullptr)
            pLogger->trace("\t\tloop block has no sub blocks");
        while (fb != nullptr)
        {
            fb->printRaw(ss);
            pLogger->trace("\tInterior subblock {0:d} identifies as\n{0:s}", index, ss.str());
            index++;
            pLogger->trace("\t\tBlock ins = {0:d}, outs = {1:d}", fb->sizeIn(), fb->sizeOut());
            fb = loopBlock->subBlock(index);
        }
        FlowBlock* parentBlock = loopBlock->getParent();
        parentBlock->printRaw(ss);
        pLogger->trace("\tThe parent basic block to our loop block identifies as:\n{0:s}", ss.str());
        ss.str("");
        pLogger->trace("\t\tParent block ins = {0:d}, outs = {1:d}", parentBlock->sizeIn(), parentBlock->sizeOut());
        // identify the output edge blocks
        for (index=0; index < loopBlock->sizeOut(); ++index)
        {
            fb = loopBlock->getOut(index);
            fb->printRaw(ss);
            pLogger->trace("\t\tParent's output block {0:d} identifies as\n{1:s}", index, ss.str());
            ss.str("");
        }
        FlowBlock* dominator = loopBlock->getImmedDom();
        dominator->printRaw(ss);
        pLogger->trace("\tThe immediate dominator block to our loop block identifies as:\n{0:s}", ss.str());
        ss.str("");
        pLogger->trace("List of FlowBlocks in the function:");
        int i = 0;
        while (i < graph.getSize())
        {
            graph.subBlock(i)->printRaw(ss);
            pLogger->trace("\t{0:s}", ss.str());
            ss.str("");
            i++;
        }
    }
    pLogger->flush();
    return TRANSFORM_COMPLETED;
}
int VectorMatcher::transformStrlen()
{
    pLogger->info("Entering VectorMatcher::transformStrlen");
    return TRANSFORM_ROLLED_BACK;
}
}
