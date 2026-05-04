#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "framework.hh"
#include "riscv_sleigh.hh"

namespace ghidra{

PcodeOp* insertVoidCallOther(Funcdata& data, const Address& addr, intb builtinOpId, Varnode* param1, Varnode* param2, Varnode* param3)
{
    // make sure this builtin is registered
    data.getArch()->userops.registerBuiltin(builtinOpId);
    // create a new Pcodeop with four varnode parameters
    PcodeOp *newOp = data.newOp(4,addr);
    data.opSetOpcode(newOp, CPUI_CALLOTHER);
    data.opSetInput(newOp, data.newConstant(4, builtinOpId), 0);
    data.opSetInput(newOp, param1, 1);
    data.opSetInput(newOp, param2, 2);
    data.opSetInput(newOp, param3, 3);
    return newOp;
}

PcodeOp* insertBranchOp(Funcdata& data, const Address& insertionPoint, Address& destinationAddr)
{
    PcodeOp *newOp = data.newOp(1, insertionPoint);
    Varnode *inlineAddr = data.newCodeRef(destinationAddr);
    data.opSetOpcode(newOp, CPUI_BRANCH);
    data.opSetInput(newOp, inlineAddr, 0);
    return newOp;
}

void getRegisterName(const Varnode* vn, std::string* regName)
{
    const Translate *trans = registerAddrSpace->getTrans();
    *regName = trans->getRegisterName(registerAddrSpace, vn->getAddr().getOffset(), 4);
}

void getRegisterName(intb offset, std::string* regName)
{
    const Translate *trans = registerAddrSpace->getTrans();
    *regName = trans->getRegisterName(registerAddrSpace, offset, 4);
}

bool sameRegister(const Varnode* a, const Varnode* b)
{
    Address aAddr = a->getAddr();
    if (aAddr.isInvalid()) return false;
    Address bAddr = b->getAddr();
    if (bAddr.isInvalid()) return false;
    if ((aAddr.getSpace() != registerAddrSpace) || (bAddr.getSpace() != registerAddrSpace)) return false;
    return aAddr.getOffset() == bAddr.getOffset();
}

void FunctionEditor::deleteOp(PcodeOp* op, const std::string& message)
{
    pLogger->info("Deleting PcodeOp {0:s} at 0x{1:x}:{2:x}",
                message, op->getAddr().getOffset(), op->getTime());
    Varnode* resultVn = op->getOut();
    if (resultVn != nullptr)
    {
        resultVn->printInfo(ss);
        pLogger->info("\tResult varnode info: {0:s}", ss.str());
        ss.str("");
        if (resultVn->isAddrTied())
            pLogger->info("\tThe result varnode is AddrTied");
        if (resultVn->isAddrForce())
            pLogger->info("\tThe result varnode is AddrForce");
        std::list<PcodeOp*>::const_iterator opIter = resultVn->beginDescend();
        while (opIter != resultVn->endDescend())
        {
            PcodeOp* descOp = *opIter++;
            pLogger->info("\tNote Descendent PcodeOp {0:s} at 0x{1:x}:{2:x}",
                        message, descOp->getAddr().getOffset(), descOp->getTime());
            descendentsToReview.insert(descOp);
        }
    }
    data.opUnlink(op);
    descendentsToReview.erase(op);
}

void FunctionEditor::removeDoWhileWrapperBlock(BlockBasic* blk)
{
    FlowBlock* parentBlock = nullptr;
    FlowBlock* grandparentBlock = nullptr;
    pLogger->info("Searching for an enclosing DoWhile block");
    FlowBlock* copyBlk = blk->getCopyMap();
    if (copyBlk == nullptr)
        pLogger->trace("\tblk->getCopyMap() returns null");
    else
    {
        parentBlock = copyBlk->getParent();
        if (parentBlock == nullptr)
            pLogger->trace("\tcopyBlk->getParent() returns null");
        else
        {
            if (logBlockStructure)
            {
                parentBlock->printRaw(ss);
                pLogger->trace("Found candidate Parent block:\n{0:s}", ss.str());
                ss.str("");
            }
            grandparentBlock = parentBlock->getParent();
            if (grandparentBlock == nullptr)
                pLogger->trace("\tparentBlock->getParent() returns null");
            else if (logBlockStructure)
            {
                grandparentBlock->printRaw(ss);
                pLogger->trace("Found candidate Grandparent block:\n{0:s}", ss.str());
                ss.str("");
            }
        }
    }
    if (grandparentBlock == nullptr) pLogger->trace("Found no grandparent block");
    else
    {
        if ((parentBlock->getType() == FlowBlock::t_dowhile) &&
            (grandparentBlock->getType() == FlowBlock::t_ls))
        {
            pLogger->info("Removing pointless DoWhile block");
            BlockList* lsb = dynamic_cast<BlockList*>(grandparentBlock);
            BlockGraph* doWhile = dynamic_cast<BlockDoWhile*>(parentBlock);
            intb index = -1;
            const vector< FlowBlock * > & list = lsb->getList();
            for (intb i = 0; i < list.size(); i++)
            {
                pLogger->trace("Checking list entry {0:d} of type {1:d}",
                    i, (int)(list[i]->getType()));
                if (list[i] == parentBlock)
                {
                    index = i;
                    break;
                }
            }
            if (index == -1)
            {
                pLogger->error("Unable to locate DoWhile block in List Block");
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
                    pLogger->info("Removing input edge from block {0:d}",
                        ib->getIndex());
                    lsb->removeEdge(ib, doWhile);
                }
                std::vector<FlowBlock*> edgesOut;
                for (int i = 0; i < doWhile->sizeOut(); i++)
                {
                    FlowBlock* ob = doWhile->getOut(i);
                    edgesOut.push_back(ob);
                    pLogger->info("Removing output edge to block {0:d}",
                        ob->getIndex());
                    lsb->removeEdge(doWhile, ob);
                }
                pLogger->info("Removing internal loop edge from vector block");
                doWhile->removeEdge(copyBlk, copyBlk);
                const BlockGraph& graph = data.getStructure();
                if (logBlockStructure)
                {
                    graph.printTree(ss, 1);
                    pLogger->trace("Full tree before block replacement:\n{0:s}", ss.str());
                    ss.str("");
                }
                // Adjust any external MULTIEQUAL PcodeOps - they can not have more varnode inputs
                // than the parent block has edges in
                std::list<ghidra::PcodeOp*>::iterator endOp = blk->endOp();
                std::list<ghidra::PcodeOp*>::iterator firstOp = blk->beginOp();
                for (auto iter = firstOp; iter != endOp; iter++)
                {
                    ghidra::PcodeOp* op = *iter;
                    if (op->code() != ghidra::CPUI_MULTIEQUAL) continue;
                    const ghidra::Varnode* outVn = op->getOut();
                    for (int slot = 0; slot < op->numInput(); ++slot)
                    {
                        if (op->getIn(slot) == outVn)
                        {
                            ghidra::pLogger->info("Trimming self-referential MULTIEQUAL Varnode input");
                            data.opRemoveInput(op, slot);
                            break;
                        }
                    }
                }
                copyBlk->setParent(grandparentBlock);
                FunctionEditor::replaceBlock(&graph, parentBlock, copyBlk);
                doWhile->removeComponentLink(copyBlk);
                if (logBlockStructure)
                {
                    graph.printTree(ss, 1);
                    pLogger->trace("Full tree after block replacement:\n{0:s}", ss.str());
                    ss.str("");
                }
                // restore the edges extracted from the doWhile block
                for (auto b: edgesIn)
                {
                    pLogger->info("Adding input edge from block {0:d} to the copy block",
                        b->getIndex());
                    lsb->addEdge(b, copyBlk);
                }
                for (auto b: edgesOut)
                {
                    pLogger->info("Adding output edge to the copy block from block {0:d} ",
                        b->getIndex());
                    lsb->addEdge(copyBlk, b);
                }
                delete doWhile;
                if (logBlockStructure)
                {
                    graph.printTree(ss, 1);
                    pLogger->trace("Full tree after dowhile deletion:\n{0:s}", ss.str());
                    ss.str("");
                }
            }
        }
    }
}

void FunctionEditor::removeUnusedOps(FlowBlock* block)
{
    std::set<PcodeOp*> deletionSet;
    bool finished = false;
    while (!finished)
    {
        PcodeOp* op = block->firstOp();
        while (true)
        {
            if (op == nullptr) break;
            Varnode* outVn = op->getOut();
            if ((outVn != nullptr) && (outVn->beginDescend() == outVn->endDescend()))
            {
                pLogger->info("Queuing for deletion PcodeOp with unused output at 0x{0:x}:{1:x}",
                    op->getAddr().getOffset(), op->getTime());
                deletionSet.insert(op);
            }
            if (op == block->lastOp()) break;
            op = op->nextOp();
        }
        finished = (deletionSet.size() == 0);
        for (auto del_op: deletionSet)
            deleteOp(del_op, "with unused output");
        deletionSet.clear();
    }
}

void FunctionEditor::simplifyBlocks(std::vector<PcodeOp*> opsToDelete, BlockBasic* loopBlock, BlockBasic* epilogBlock, std::vector<FlowBlock*>* relatedBlocks)
{
    std::set<PcodeOp*> uniqueOpsToDelete(opsToDelete.begin(), opsToDelete.end());
    for (auto op: uniqueOpsToDelete)
    {
        inspector->log("Deleting from uniqueOpsToDelete:", op);
        deleteOp(op, "FunctionEditor::simplifyBlocks");
    }
    pLogger->info("Preparing to edit the flow block graph to remove the loop edge");
    BlockGraph& graph = data.getStructure();
    graph.removeEdge(loopBlock, loopBlock);
    removeDoWhileWrapperBlock(loopBlock);
    if (epilogBlock != nullptr)
        removeUnusedOps(epilogBlock);
    removeUnusedOps(loopBlock);
    if (relatedBlocks != nullptr)
        for (auto fb: *relatedBlocks)
            removeUnusedOps(fb);
    if (pLogger->should_log(spdlog::level::trace))
    {
        inspector->log("copyBlk after replacement", loopBlock->getCopyMap());
    }
    // Remove stale, free varnodes from any MULTIEQUAL PcodeOp descendents
    if (!descendentsToReview.empty())
    {
        std::set<PcodeOp*> descendentsFixed;
        pLogger->trace("Preparing to trim any free varnode references in MULTIEQUAL or function call parameter lists");
        for (auto op: descendentsToReview)
        {
            bool opFixed = false;
            if (op->code() == CPUI_MULTIEQUAL)
            {
                for (int slot = 0; slot < op->numInput(); slot++)
                {
                    Varnode* vn = op->getIn(slot);
                    if (vn->isFree() && (vn->getAddr().getSpace() == registerAddrSpace))
                    {
                        op->printRaw(ss);
                        if (op->numInput() == 2)
                        {
                            int goodSlot;
                            if (slot == 0) goodSlot = 1;
                            else goodSlot = 0;
                            pLogger->info("\tPreparing to replace slot {1:d} from PcodeOp {0:s} via duplication",
                                ss.str(), slot);
                            ss.str("");
                            data.opRemoveInput(op, slot);
                            data.opInsertInput (op, op->getIn(goodSlot), slot);
                        }
                        else {
                            pLogger->info("\tPreparing to remove slot {1:d} from MULTIEQUAL PcodeOp {0:s}",
                            ss.str(), slot);
                            data.opRemoveInput(op, slot);
                            slot--;
                            ss.str("");
                        }
                        op->printRaw(ss);
                        pLogger->info("\t\tResulting PcodeOp is {0:s}",
                            ss.str());
                        ss.str("");
                        opFixed = true;
                    }
                }
            }
            else if (op->code() == CPUI_CALL)
            {
                for (int slot = 0; slot < op->numInput(); slot++)
                {
                    Varnode* vn = op->getIn(slot);
                    if (vn->isFree())
                    {
                        op->printRaw(ss);
                        pLogger->info("\tPreparing to remove slot {1:d} from CALL PcodeOp {0:s}",
                                ss.str(), slot);
                        data.opRemoveInput(op, slot);
                        opFixed = true;
                        ss.str("");
                        slot--;
                    }
                }
            }
            if (opFixed) descendentsFixed.insert(op);
        }
        for (auto op: descendentsFixed)
            descendentsToReview.erase(op);
    }
    if (!descendentsToReview.empty())
    {
        pLogger->error("PcodeOps with free Varnodes still exist - decompiler will abort:");
        for (auto op: descendentsToReview)
        {
            op->printRaw(ss);
            pLogger->warn("\tPcode at 0x{0:x}:{1:x}  {2:s}",
                op->getAddr().getOffset(), op->getTime(), ss.str());
            ss.str("");
        }
    }
    if (pLogger->should_log(spdlog::level::trace))
    {
        data.printRaw(ss);
        pLogger->trace("Final function Pcode after transform:\n{0:s}", ss.str());
        ss.str("");
    }
    if (inspector->audit_multiequals)
    {
        inspector->auditMultiequals(data, ss);
        pLogger->trace("Multiequal audit results:\n{0:s}", ss.str());
        ss.str("");
    }
    pLogger->trace("FunctionEditor::simplifyBlocks exits");
}

void FunctionEditor::replaceBlock(const BlockGraph* graph, FlowBlock* oldBlock, FlowBlock* newBlock)
{
    if (graph->getType() == FlowBlock::t_plain) return;

    vector<FlowBlock*>& list = const_cast<vector<FlowBlock*>&>(graph->getList());
    for(auto iter=list.begin();iter!=list.end();++iter)
    {
        if ((*iter)->getType() == FlowBlock::t_plain) continue;
        if ((*iter)->getType() == FlowBlock::t_copy) continue;
        BlockGraph* bg = dynamic_cast<BlockGraph*>(*iter);
        if (*iter == oldBlock)
        {
            pLogger->info("\tReplacing oldBlock reference in BlockGraph index {0:d}", bg->getIndex());
            *iter = newBlock;
        }
        if ((*iter)->getType() == FlowBlock::t_if)
        {
            BlockIf* blkIf = dynamic_cast<BlockIf*>(bg);
            if (blkIf->getGotoTarget() == oldBlock)
            {
                pLogger->info("\tReplacing oldBlock reference in BlockIf");
                blkIf->setGotoTarget(newBlock);
            }
        }
        if ((*iter)->getType() == FlowBlock::t_goto)
        {
            BlockGoto* blkGt = dynamic_cast<BlockGoto*>(bg);
            if (blkGt->getGotoTarget() == oldBlock)
            {
                pLogger->info("\tReplacing oldBlock reference in a new BlockGoto");
                blkGt->setGotoTarget(newBlock);
            }
        }
        // recurse into subblocks, but not into goto targets
        FunctionEditor::replaceBlock(bg, oldBlock, newBlock);
    }
}

void BlockGraphEditor::collectSubBlocks(std::vector<const FlowBlock*>& list) const
{
    for (int i = 0; i < graph.getSize(); i++)
        list.push_back(graph.subBlock(i));
}
}
