#include <iostream>
#include <fstream>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

#include "riscv.hh"
#include "diagnostics.hh"
#include "vectorcopy.hh"
#include "vector_loop_match.hh"
#include "utility.hh"

namespace ghidra {

RuleVectorCopy::RuleVectorCopy(const string &g) : 
    Rule(g, 0, "vectorcopy") {}

Rule* RuleVectorCopy::clone(const ActionGroupList &grouplist) const
{
    if (!grouplist.contains(getGroup())) {
        pluginLogger->error("RuleVectorCopy::clone failed for lack of a group");
        return (Rule *)0;
    }
    pluginLogger->trace("Prepared a new RuleVectorCopy for Action database");
    pluginLogger->flush();
    return new RuleVectorCopy(getGroup());
}

/**
 * @brief ask for callbacks on any CALLOTHER ops
 * @details this will include all user pcode op invocations
 * 
 * @param oplist 
 */
void RuleVectorCopy::getOpList(vector<uint4> &oplist) const {
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
int4 RuleVectorCopy::applyOp(PcodeOp *firstOp, Funcdata &data) {

    int4 returnCode = 0;
    bool vsetImmediate;
    bool vsetRegister;
    bool trace = pluginLogger->should_log(spdlog::level::trace);
    pluginLogger->trace("Vector context discovered");
    // require one of several vset* instructions to begin this pattern,
    // adjusting the maximum number of pcode ops to examine
    const RiscvUserPcode* vsetInfo = RiscvUserPcode::getUserPcode(*firstOp);
    if (vsetInfo == nullptr) return 0;
    vsetImmediate = vsetInfo->isVseti;
    vsetRegister = vsetInfo->isVset;
    if (!(vsetImmediate || vsetRegister)) return 0;
    // we have a vsetivli or a vsetvli instruction
    pluginLogger->trace("Entering applyOp with a recognized vset* user pcode op at 0x{0:x}",
        firstOp->getAddr().getOffset());
    // The size, or total number of elements to process, will be a constant
    // for vsetivli instructions or a register for vsetvl instructions
    Varnode* size_varnode = firstOp->getIn(1);
    // Examine the vsetivli instr to get multiplier and element size
    if (vsetImmediate && !size_varnode->isConstant())
    {
        pluginLogger->warn("Found a vseti instruction with a non-constant argument");
        return 0;
    }
    int4 numBytesPerPass = vsetInfo->multiplier * vsetInfo->elementSize;
    int4 numBytes;
    if (vsetImmediate)
    {
        numBytes = size_varnode->getOffset() * numBytesPerPass;
        // search forward in the block for a PcodeOp that may begin the pattern we
        // which to replace.  Stop the search after 30 pcode ops
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
                if (trace) displayPcodeOp(*op, "vector sequence start op", true);
                // find the descendents reading the output vector register
                Varnode* sourceVn = op->getIn(1);
                bool isMemset = sourceVn->isConstant() && opInfo->isLoadImmediate;
                intb builtinOp;
                if (isMemset) builtinOp = VECTOR_MEMSET;
                else builtinOp = VECTOR_MEMCPY;
                Varnode* outputVn = op->getOut();
                std::vector<std::pair<PcodeOp*,PcodeOp*>*> pcodesToBeBuilt;
                std::list<PcodeOp*>::const_iterator enditer = outputVn->endDescend();
                for (std::list<PcodeOp*>::const_iterator it=outputVn->beginDescend(); it!=enditer; ++it)
                {
                    const RiscvUserPcode* descOpInfo = RiscvUserPcode::getUserPcode(**it);
                    // we only replace vector store opcodes
                    if ((descOpInfo == nullptr) || !descOpInfo->isStore)
                        continue;
                    PcodeOp* newOp;
                    pluginLogger->info("Inserting vector op 0x{0:x} at 0x{1:x}",
                        builtinOp, (*it)->getAddr().getOffset());
                    if (trace) displayPcodeOp(**it, "Dependent pcode:", true);
                    Varnode * new_size_varnode = data.newConstant(1, numBytes);
                    newOp = insertBuiltin(data, **it, builtinOp, (*it)->getIn(2), sourceVn, new_size_varnode);
                    pcodesToBeBuilt.push_back(new std::pair<PcodeOp*,PcodeOp*>(newOp, *it));
                    deleteSet.push_back(*it);
                    returnCode = 1;
                }
                for (auto it: pcodesToBeBuilt) {

                    data.opInsertBefore(it->first, it->second);
                    delete it;
                }
                pluginLogger->info("Deleting op at 0x{0:x}", op->getAddr().getOffset());
                deleteSet.push_back(op);
            }
            op = op->nextOp();
            ++numPcodes;
        }
        if (noVectorOpsFound)
        {
            pluginLogger->info("Deleting firstOp at 0x{0:x}", firstOp->getAddr().getOffset());
            data.opUnlink(firstOp);
        }
        for (auto iter: deleteSet)
        {
            pluginLogger->info("Deleting op at 0x{0:x}", iter->getAddr().getOffset());
            data.opUnlink(iter);
        }
        return returnCode;
    }
    // We have a vsetvl instruction and likely a loop, so
    // construct something to start the analysis.
    VectorLoopMatch matcher(data, firstOp);
    if (!matcher.analysisEnabled) return 0;
    matcher.analyze();
    if (matcher.isMemcpy())
    {
        return matcher.transform();
    }
    return 0;
}
}