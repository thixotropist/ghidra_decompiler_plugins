#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "framework.hh"

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
            std::stringstream ss;
            parentBlock->printRaw(ss);
            pLogger->trace("Found candidate Parent block:\n{0:s}", ss.str());
            grandparentBlock = parentBlock->getParent();
            ss.str("");
            if (grandparentBlock == nullptr)
                pLogger->trace("\tparentBlock->getParent() returns null");
            else
            {
                grandparentBlock->printRaw(ss);
                pLogger->trace("Found candidate Grandparent block:\n{0:s}", ss.str());
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
                    lsb->removeEdge(ib, doWhile);
                }
                std::vector<FlowBlock*> edgesOut;
                for (int i = 0; i < doWhile->sizeOut(); i++)
                {
                    FlowBlock* ob = doWhile->getOut(i);
                    edgesOut.push_back(ob);
                    lsb->removeEdge(doWhile, ob);
                }
                pLogger->info("Removing internal loop edge from vector block");
                doWhile->removeEdge(copyBlk, copyBlk);
                const BlockGraph& graph = data.getStructure();
                std::stringstream ss;
                graph.printTree(ss, 1);
                pLogger->trace("Full tree before block replacement:\n{0:s}", ss.str());
                ss.str("");
                copyBlk->setParent(grandparentBlock);
                FunctionEditor::replaceBlock(&graph, parentBlock, copyBlk);
                doWhile->removeComponentLink(copyBlk);
                graph.printTree(ss, 1);
                pLogger->trace("Full tree after block replacement:\n{0:s}", ss.str());
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
                pLogger->trace("Full tree after dowhile deletion:\n{0:s}", ss.str());
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
            pLogger->trace("Testing PcodeOp at 0x{0:x} for unused outputs",
                op->getAddr().getOffset());
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
        {
            pLogger->info("Deleting PcodeOp with unused output at 0x{0:x}:{1:x}",
                    op->getAddr().getOffset(), del_op->getTime());
            data.opUnlink(del_op);
        }
        deletionSet.clear();
    }
}

void BlockGraphEditor::collectSubBlocks(std::vector<const FlowBlock*>& list) const
{
    for (int i = 0; i < graph.getSize(); i++)
    {
        list.push_back(graph.subBlock(i));
    }
}

void FunctionEditor::replaceBlock(const BlockGraph* graph, FlowBlock* oldBlock, FlowBlock* newBlock)
{
    pLogger->trace("Entering replaceBlock");
    if (graph->getType() == FlowBlock::t_plain) return;

    vector<FlowBlock*>& list = const_cast<vector<FlowBlock*>&>(graph->getList());
    for(auto iter=list.begin();iter!=list.end();++iter)
    {
        if ((*iter)->getType() == FlowBlock::t_plain) continue;
        if ((*iter)->getType() == FlowBlock::t_copy) continue;
        BlockGraph* bg = dynamic_cast<BlockGraph*>(*iter);
        if (*iter == oldBlock)
        {
            pLogger->trace("\tReplacing oldBlock reference in BlockGraph index {0:d}",
                bg->getIndex());
            *iter = newBlock;
        }
        if ((*iter)->getType() == FlowBlock::t_if)
        {
            BlockIf* blkIf = dynamic_cast<BlockIf*>(bg);
            pLogger->trace("\tChecking BlockIf index {0:d}",
                blkIf->getIndex());
            if (blkIf->getGotoTarget() == oldBlock)
            {
                pLogger->trace("\tReplacing oldBlock reference in BlockIf");
                blkIf->setGotoTarget(newBlock);
            }
        }
        if ((*iter)->getType() == FlowBlock::t_goto)
        {
            BlockGoto* blkGt = dynamic_cast<BlockGoto*>(bg);
            pLogger->trace("\tChecking BlockGoto index {0:d}",
                blkGt->getIndex());
            if (blkGt->getGotoTarget() == oldBlock)
            {
                pLogger->trace("\tReplacing oldBlock reference in a new BlockGoto");
                blkGt->setGotoTarget(newBlock);
            }
        }
        // recurse into subblocks, but not into goto targets
        FunctionEditor::replaceBlock(bg, oldBlock, newBlock);
    }
}
}
