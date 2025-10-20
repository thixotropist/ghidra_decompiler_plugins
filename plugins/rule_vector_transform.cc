#include <iostream>
#include <fstream>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

#include "riscv.hh"

#include "rule_vector_transform.hh"
#include "vector_matcher.hh"
#include "framework.hh"

namespace ghidra {

static int evaluateNonLoopVectorStanza(PcodeOp *firstOp, VectorMatcher& matcher, Funcdata &data, const RiscvUserPcode* vsetInfo)
{
    if (transformCountNonLoop >= TRANSFORM_LIMIT_NONLOOPS)
        return 0;
    int returnCode = RETURN_NO_TRANSFORM;
    // search forward in the block for a PcodeOp that may begin the pattern we
    // which to replace.  Stop the search after 30 pcode ops or the first vset* instruction.
    // For each vector load or load immediate instruction, collect any vector dependencies.
    // For each vector dependency in the form of a vector store operation, convert the
    // load and store ops into vector_memset or vector_memcpy invocations.
    // This is the only current loop-free vector pattern - refactor when we find others.
    PcodeOp *op = firstOp->nextOp();
    int numPcodes = 1;
    std::vector<PcodeOp *> deleteSet; ///< collect PcodeOps to delete if we get a successful transform
    bool noVectorOpsFound = true;
    // inspect this block, within limits, for relevant vector ops
    while ((op != nullptr) && (numPcodes < 30))
    {
        const RiscvUserPcode *opInfo = RiscvUserPcode::getUserPcode(*op);
        if (opInfo == nullptr)
        {
            op = op->nextOp();
            ++numPcodes;
            continue;
        };
        // stop scanning if this is another vset instruction
        if (opInfo->isVset || opInfo->isVseti)
        {
            break;
        }
        // stop scanning if we have iterated into another block
        if (op->getParent() != firstOp->getParent())
            break;
        noVectorOpsFound = noVectorOpsFound && !opInfo->isVectorOp;
        // is this a vector load or load immediate?  If so, search and process any
        // matching vector store ops
        if (opInfo->isLoad || opInfo->isLoadImmediate)
        {
            // There may be multiple vector store ops for each vector load op
            // is the source an address to be copied or a constant to be stored?
            Varnode *sourceVn = op->getIn(1);
            bool isMemset = sourceVn->isConstant() && opInfo->isLoadImmediate;
            intb builtinOp;
            if (isMemset)
                builtinOp = VECTOR_MEMSET;
            else
                builtinOp = VECTOR_MEMCPY;
            // iterate over the descendents reading the output vector register
            Varnode *outputVn = op->getOut();
            std::vector<std::pair<PcodeOp *, PcodeOp *> *> pcodesToBeBuilt;
            std::list<PcodeOp *>::const_iterator enditer = outputVn->endDescend();
            for (std::list<PcodeOp *>::const_iterator it = outputVn->beginDescend(); it != enditer; ++it)
            {
                const RiscvUserPcode *descOpInfo = RiscvUserPcode::getUserPcode(**it);
                // we only transform vector store opcodes
                if ((descOpInfo == nullptr) || !descOpInfo->isStore)
                    continue;
                pLogger->info("Inserting vector op 0x{0:x} at 0x{1:x}",
                                builtinOp, (*it)->getAddr().getOffset());
                // vector_mem* invocations count bytes, not elements.
                int4 numBytes = matcher.vNumElem->getOffset() * vsetInfo->multiplier * vsetInfo->elementSize;
                // construct a new constant Varnode to hold the number of bytes
                Varnode *new_size_varnode = data.newConstant(1, numBytes);
                Varnode *destVn = (*it)->getIn(2);
                // we have destination, source, and size so construct the vector_mem* op
                PcodeOp *newOp = insertVoidCallOther(data, (*it)->getAddr(), builtinOp, destVn, sourceVn, new_size_varnode);
                // accumulate pcode additions and deletions as a pending transaction
                pcodesToBeBuilt.push_back(new std::pair<PcodeOp *, PcodeOp *>(newOp, *it));
                deleteSet.push_back(*it);
                ++transformCountNonLoop;
                returnCode = RETURN_TRANSFORM_PERFORMED;
            }
            for (auto it : pcodesToBeBuilt)
            {
                // queue pending vector_mem* insertions
                data.opInsertBefore(it->first, it->second);
                delete it;
            }
            pLogger->info("Queuing deletion of op at 0x{0:x}", op->getAddr().getOffset());
            deleteSet.push_back(op);
        }
        op = op->nextOp();
        ++numPcodes;
    }
    if (noVectorOpsFound)
    {
        pLogger->info("Found possible orphan vset op at 0x{0:x}", firstOp->getAddr().getOffset());
    }
    else
    {
        // queue deletion of the vector load op
        deleteSet.push_back(firstOp);
    }
    // complete any queued deletions, removing descendents as well.
    for (auto iter : deleteSet)
    {
        pLogger->info("Attempting deletion of vector op at 0x{0:x}", iter->getAddr().getOffset());
        Varnode *outVn = iter->getOut();
        if (outVn == nullptr)
        {
            pLogger->info("Deleting vector op at 0x{0:x}", iter->getAddr().getOffset());
            data.opUnlink(iter);
        }
        else
        {
            std::list<PcodeOp *>::const_iterator endIter = outVn->endDescend();
            std::list<PcodeOp *>::const_iterator startIter = outVn->beginDescend();
            if (startIter == endIter)
            {
                pLogger->info("Deleting vector op at 0x{0:x}", iter->getAddr().getOffset());
                data.opUnlink(iter);
            }
        }
    }
    return returnCode;
}

RuleVectorTransform::RuleVectorTransform(const string &g) :
    Rule(g, 0, "vectorTransforms") {}

Rule* RuleVectorTransform::clone(const ActionGroupList &grouplist) const
{
    if (!grouplist.contains(getGroup())) {
        pLogger->error("RuleVectorTransform::clone failed for lack of a group");
        return (Rule *)0;
    }
    pLogger->trace("Prepared a new RuleVectorTransform for Action database");
    pLogger->flush();
    return new RuleVectorTransform(getGroup());
}

void RuleVectorTransform::getOpList(vector<uint4> &oplist) const {
    oplist.push_back(CPUI_CALLOTHER);
}

int4 RuleVectorTransform::applyOp(PcodeOp *firstOp, Funcdata &data) {

    [[maybe_unused]] bool trace = pLogger->should_log(spdlog::level::trace);
    pLogger->trace("Vector context discovered");
    // require one of several vset* instructions to begin this pattern,
    // adjusting the maximum number of pcode ops to examine
    const RiscvUserPcode* vsetInfo = RiscvUserPcode::getUserPcode(*firstOp);
    if (vsetInfo == nullptr) return RETURN_NO_TRANSFORM;
    // construct a VectorMatcher to start the analysis.
    VectorMatcher matcher(data, firstOp);
    bool vsetImmediate = vsetInfo->isVseti;
    bool vsetRegister = vsetInfo->isVset;
    if (!(vsetImmediate || vsetRegister)) return RETURN_NO_TRANSFORM;
    // we have a vsetivli or a vsetvli instruction
    pLogger->trace("Entering applyOp with a recognized vset* user pcode op at 0x{0:x}",
        firstOp->getAddr().getOffset());
    // If the firstOp is a vseti instruction, there is no loop and we can handle it locally
    if (vsetImmediate) return evaluateNonLoopVectorStanza(firstOp, matcher, data, vsetInfo);
    // Otherwise, this must be a vset and is likely a loop requiring much more processing
    pLogger->trace("Testing the vector stanza for a vector_memcpy match");
    if (matcher.isMemcpy())
    {
        if (transformCountLoop >= TRANSFORM_LIMIT_LOOPS) return 0;
        ++transformCountLoop;
        return matcher.transformMemcpy();
    }
    pLogger->trace("Testing the vector stanza for a vector_strlen match");
    if (matcher.isStrlen())
    {
        if (transformCountLoop >= TRANSFORM_LIMIT_LOOPS) return 0;
        ++transformCountLoop;
        return matcher.transformStrlen();
    }
    return RETURN_NO_TRANSFORM;
}
}
