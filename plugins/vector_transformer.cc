#include <iostream>
#include <fstream>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

#include "riscv.hh"
#include "diagnostics.hh"
#include "vector_transformer.hh"
#include "vector_matcher.hh"
#include "utility.hh"

namespace ghidra {

RuleVectorTransform::RuleVectorTransform(const string &g) : 
    Rule(g, 0, "vectorTransforms") {}

Rule* RuleVectorTransform::clone(const ActionGroupList &grouplist) const
{
    if (!grouplist.contains(getGroup())) {
        pluginLogger->error("RuleVectorTransform::clone failed for lack of a group");
        return (Rule *)0;
    }
    pluginLogger->trace("Prepared a new RuleVectorTransform for Action database");
    pluginLogger->flush();
    return new RuleVectorTransform(getGroup());
}

/**
 * @brief ask for callbacks on any CALLOTHER ops
 * @details this will include all user pcode op invocations
 * 
 * @param oplist 
 */
void RuleVectorTransform::getOpList(vector<uint4> &oplist) const {
    oplist.push_back(CPUI_CALLOTHER);
}

/**
 * @brief Does the current block match a vector copy or memset rule?
 * @details Currently only handles loop-free sequences commonly found
 *          in initialization code.
 * 
 * @param firstOp a CALLOTHER opcode that *might* reference a vset userPcodeop
 * @param data Context for the enclosing function
 * @return int4 
 */
int4 RuleVectorTransform::applyOp(PcodeOp *firstOp, Funcdata &data) {

    const int RETURN_NO_TRANSFORM = 0;
    const int RETURN_TRANSFORM_PERFORMED = 1;
    pluginLogger->trace("Testing for early termination of the transform search");
    if (transformCount >= TRANSFORM_LIMIT) return 0;
    int4 returnCode = RETURN_NO_TRANSFORM;
    bool trace = pluginLogger->should_log(spdlog::level::trace);
    pluginLogger->trace("Vector context discovered");
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
    pluginLogger->trace("Entering applyOp with a recognized vset* user pcode op at 0x{0:x}",
        firstOp->getAddr().getOffset());
    if (vsetImmediate)
    {
        // search forward in the block for a PcodeOp that may begin the pattern we
        // which to replace.  Stop the search after 30 pcode ops or the first vset* instruction.
        // For each vector load or load immediate instruction, collect any vector dependencies.
        // For each vector dependency in the form of a vector store operation, convert the
        // load and store ops into vector_memset or vector_memcpy invocations.
        // This is the only current loop-free vector pattern - refactor when we find others.
        PcodeOp* op = firstOp->nextOp();
        int numPcodes = 1;
        std::vector<PcodeOp*> deleteSet;
        bool noVectorOpsFound = true;
        while ((op != nullptr) && (numPcodes < 30))
        {
            const RiscvUserPcode* opInfo = RiscvUserPcode::getUserPcode(*op);
            if (opInfo == nullptr) {
                op = op->nextOp();
                ++numPcodes;
                continue;
            };
            // fail the match if this is another vset instruction
            if (opInfo->isVset || opInfo->isVseti) {
                break;
            }
            noVectorOpsFound = noVectorOpsFound && !opInfo->isVectorOp;
            // is this a vector load or load immediate?
            if (opInfo->isLoad || opInfo->isLoadImmediate)
            {
                // There may be multiple vector store ops for each vector load op
                if (trace) displayPcodeOp(*op, "vector sequence start op", true);
                // is the source an address to be copied or a constant to be stored?
                Varnode* sourceVn = op->getIn(1);
                bool isMemset = sourceVn->isConstant() && opInfo->isLoadImmediate;
                intb builtinOp;
                if (isMemset) builtinOp = VECTOR_MEMSET;
                else builtinOp = VECTOR_MEMCPY;
                // find the descendents reading the output vector register
                Varnode* outputVn = op->getOut();
                std::vector<std::pair<PcodeOp*,PcodeOp*>*> pcodesToBeBuilt;
                std::list<PcodeOp*>::const_iterator enditer = outputVn->endDescend();
                for (std::list<PcodeOp*>::const_iterator it=outputVn->beginDescend(); it!=enditer; ++it)
                {
                    const RiscvUserPcode* descOpInfo = RiscvUserPcode::getUserPcode(**it);
                    // we only replace vector store opcodes
                    if ((descOpInfo == nullptr) || !descOpInfo->isStore)
                        continue;
                    pluginLogger->info("Inserting vector op 0x{0:x} at 0x{1:x}",
                        builtinOp, (*it)->getAddr().getOffset());
                    if (trace) displayPcodeOp(**it, "Dependent pcode:", true);
                    // vector_mem* invocations count bytes, not elements.
                    int4 numBytes = matcher.vNumElem->getOffset() * vsetInfo->multiplier * vsetInfo->elementSize;
                    Varnode * new_size_varnode = data.newConstant(1, numBytes);
                    Varnode* destVn = (*it)->getIn(2);
                    PcodeOp* newOp = insertBuiltin(data, **it, builtinOp, destVn, sourceVn, new_size_varnode);
                    pcodesToBeBuilt.push_back(new std::pair<PcodeOp*,PcodeOp*>(newOp, *it));
                    deleteSet.push_back(*it);
                    ++transformCount;
                    returnCode = RETURN_TRANSFORM_PERFORMED;
                }
                for (auto it: pcodesToBeBuilt) {
                    // queue pending vector_mem* insertions
                    data.opInsertBefore(it->first, it->second);
                    delete it;
                }
                pluginLogger->info("Queuing deletion of op at 0x{0:x}", op->getAddr().getOffset());
                deleteSet.push_back(op);
            }
            op = op->nextOp();
            ++numPcodes;
        }
        if (noVectorOpsFound)
        {
            pluginLogger->warn("Deleting orphan vset op at 0x{0:x}", firstOp->getAddr().getOffset());
            data.opUnlink(firstOp);
        }
        for (auto iter: deleteSet)
        {
            pluginLogger->info("Deleting vector op at 0x{0:x}", iter->getAddr().getOffset());
            data.opUnlink(iter);
        }
        return returnCode;
    }
    // this must be a vset and is likely a loop
    if (!matcher.analysisEnabled) return RETURN_NO_TRANSFORM;
    matcher.analyze();
    if (matcher.isMemcpy())
    {
        ++transformCount;
        return matcher.transform();
    }
    return 0;
}
}