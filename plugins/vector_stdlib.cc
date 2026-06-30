/**
 * @file vector_stdlib.cc
 * @author thixotropist
 * @brief Provides vector transform code for vectorized C routines like memcpy, strlen, strcmp
 * @date 2026-23-03
 *
 * @copyright Copyright (c) 2026
 *
 */
#include <string>
#include <sstream>
#include <set>
#include <algorithm>
#include <iterator>
#include <ranges>

#include "spdlog/spdlog.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/type.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/address.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"

#include "framework.hh"
#include "riscv.hh"
#include "vector_matcher.hh"
#include "vector_ops.hh"

namespace riscv_vector
{

/**
 * @brief The epilog to a vector+strlen loop can show significant variation.
 *        Try to capture the variants with this enumeration
 */
enum StrlenEpilogType
{
    STRLEN,    ///< a simple strlen epilog with two integer opcodes
    STREND,    ///< a variant that returns a pointer to the last character in the string
    NOMATCH    ///< unrecognized epilog
};

bool VectorMatcher::isMemcpy()
{
    // apply generic tests first
    bool pre_match =
        (loopModel.loopFlags == 0x0) &&              // no flagged features
        loopModel.simpleFlowStructure &&             // no other  branches or calls
        (loopModel.vectorOps.size() == 3) &&         // vset, vload, vstore
        (loopModel.scalarOps.size() >= 5) &&         // expected pointer and counter arithmetic
        (loopModel.otherScalarOps.size() == 0) &&    // no other ghidra pcodeops
        (loopModel.unhandledVectorOps.size() == 0) &&    // no unhandled vector instructions
        (loopModel.otherUserPcodes.size() == 0);     // no other CALL_OTHER
    // add more complex tests specific to this pattern
    bool match = pre_match && vectorRegistersMatch;  // vector load and store use the same register
    return match;
}

int VectorMatcher::transformMemcpy()
{
    std::stringstream ss;
    std::vector<ghidra::PcodeOp*> opsToDelete; // accumulate ops we are sure to delete in any transform
    if (ghidra::info)
        ghidra::inspector->log("before memcpy transform, ", loopBlock);
    if (loopModel.unresolvedDependencies(loopModel.terminationBranchOp))
    {
        ghidra::pLogger->warn("Unable to complete transform due to one or more references to a loop-local Varnode");
        ghidra::pLogger->flush();
        return TRANSFORM_ROLLED_BACK;
    }
    ghidra::pLogger->info("Transforming selection into vector_memcpy");
    data.getArch()->userops.registerBuiltin(VECTOR_MEMCPY);
    // Note: after this point pcode changes are irreversible

    // create a new Pcodeop with two varnode input parameters and one output varnode
    ghidra::PcodeOp *newVectorOp = data.newOp(4, loopBlock->getStop());
    data.opSetOpcode(newVectorOp, ghidra::CPUI_CALLOTHER);
    data.opSetInput(newVectorOp, data.newConstant(4, VECTOR_MEMCPY), 0);
    data.opSetInput(newVectorOp, loopModel.vDestinationOperands[0]->pExternal, 1);
    data.opSetInput(newVectorOp, loopModel.vSourceOperands[0]->pExternal, 2);
    data.opSetInput(newVectorOp, loopModel.numElements, 3);

    if (ghidra::trace)
    {
        newVectorOp->printRaw(ss);
        ghidra::pLogger->info("\tInserting a new vector operation\n\t\t{0:s}", ss.str());
        ss.str("");
    }
    data.opInsertEnd(newVectorOp, loopBlock);
    std::copy(std::begin(loopModel.loopOps), std::end(loopModel.loopOps),
        std::back_inserter(opsToDelete));
    std::copy(std::begin(loopModel.phiNodesAffectedByLoop), std::end(loopModel.phiNodesAffectedByLoop),
        std::back_inserter(opsToDelete));
    functionEditor.simplifyBlocks(opsToDelete, loopBlock, nullptr, &loopModel.relatedBlocks);
    ghidra::pLogger->flush();
    return TRANSFORM_COMPLETED;
}

bool VectorMatcher::isStrlen()
{
    bool match =
        (loopModel.loopFlags == RISCV_VEC_INSN_FAULT_ONLY_FIRST) && // vector fault only first load
        loopModel.simpleFlowStructure &&            // no other  branches or calls
        (loopModel.vectorOps.size() == 4) &&        // vset, vload, vseq, vfirst
        (loopModel.scalarOps.size() == 3) &&        // expected pointer and counter arithmetic
        (loopModel.otherScalarOps.size() == 0) &&   // no other ghidra pcodeops
        (loopModel.unhandledVectorOps.size() == 0) &&   // no unhandled vector instructions
        (loopModel.otherUserPcodes.size() == 0) &&  // no other CALL_OTHER
        (loopModel.vSourceOperands.size() == 1);    // one recognized source operand
    return match;
}

int VectorMatcher::transformStrlen()
{
    std::stringstream ss;
    std::vector<ghidra::PcodeOp*> opsToDelete; // accumulate ops we are sure to delete in any transform
    const ghidra::PcodeOp* result = nullptr;
    const ghidra::Varnode* resultVn = nullptr;
    ghidra::Varnode* sourceVn = loopModel.vSourceOperands[0]->pExternal;
    if (ghidra::info)
        ghidra::inspector->log("before strlen transform, ", loopBlock);
    // first identify the result Varnode as the register-typed varnode descending
    // from both the source load address pointer and the termination comparison operation.
    // we want the first such descendent found in the epilog following at least two
    // integer additions or subtractions
    VectorEpilogProcessor epiProc(data, loopModel);
    std::vector<ghidra::Varnode*> resultsVector;
    epiProc.getIntersectionVector(resultsVector, loopModel.vSourceOperands[0]->pRegister, loopModel.comparisonVarnode);
    if ((resultsVector.size() == 0) || (resultsVector[0] == nullptr))
    {
        ghidra::pLogger->info("Unable to find resultVn, abandon strlen transform");
        ghidra::pLogger->flush();
        return TRANSFORM_ROLLED_BACK;
    }
    // assume this is a valid vector_strlen with a normal epilog
    StrlenEpilogType epiType = STRLEN;
    // if there is only one candidate, use it.
    if (resultsVector.size() == 1)
    {
        // only one candidate, probably due to preceding temporaries
        resultVn = resultsVector[0];
    }
    else
    {
        // the strlen epilog involves two integer additions or one integer addition and one subtraction
        // Use the first intersection result Varnode candidate that is or follows the second such op
        int addSubtractCount = 0;
        for (auto op: loopModel.epilogPcodes)
        {
            ghidra::OpCode opcode = op->code();
            if (ghidra::trace)
            {
                ghidra::inspector->log("Examine epilog pcode as a possible result", op);
                ghidra::pLogger->trace("\topcode = {0:d}", static_cast<int>(opcode));
            }
            bool addOrSub =
                (opcode == ghidra::CPUI_INT_ADD) ||
                (opcode == ghidra::CPUI_PTRADD) ||
                (opcode == ghidra::CPUI_INT_SUB) ||
                (opcode == ghidra::CPUI_PTRSUB);
            if (!addOrSub) continue;
            addSubtractCount++;
            if ((addSubtractCount >= 2) &&
                (std::find(resultsVector.begin(), resultsVector.end(), op->getOut()) != resultsVector.end()))
            {
                ghidra::inspector->log("Confirm epilog pcode as the definitive result", op);
                // if the op adds a constant - probably -1 - then it is likely a string end transform
                // and is not currently handled
                const ghidra::Varnode* arg0 =  op->getIn(0);
                const ghidra::Varnode* arg1 =  op->getIn(1);
                if (arg0->isConstant() || arg1->isConstant())
                {
                    // probable, assuming the constant is -1
                    ghidra::pLogger->info("Epilog specialization for vector_strlen not yet implemented");
                    epiType = STREND;
                    break;
                }
                resultVn = op->getOut();
                break;
            }
        }
    }
    // Survey epilog structures to see if we need more special case handling
    if (COLLECT_STRLEN_SAMPLES)
    {
        strlenSampleFile << "Loop start address: 0x" << std::hex <<
            loopModel.firstAddr << std::endl << std::dec;
        strlenSampleFile << "Source Varnode: ";
        sourceVn->printRaw(strlenSampleFile);
        strlenSampleFile << std::endl;
        strlenSampleFile << "Loop instructions:" << std::endl;
        std::ranges::subrange viewOps{loopBlock->beginOp(), loopBlock->endOp()};
        for (auto op: viewOps)
        {
            strlenSampleFile << "\t";
            op->printRaw(strlenSampleFile);
            strlenSampleFile << std::endl;
        }
        const ghidra::PcodeOp* epiOp = loopBlock->lastOp()->nextOp();
        const int EPILOG_SEARCH_DEPTH = 6;
        int opCount = 0;
        strlenSampleFile << "Epilog instructions:" << std::endl;
        while ((opCount < EPILOG_SEARCH_DEPTH) && (epiOp != nullptr))
        {
            strlenSampleFile << "\t";
            epiOp->printRaw(strlenSampleFile);
            strlenSampleFile << std::endl;
            epiOp = epiOp->nextOp();
            ++opCount;
        }
        strlenSampleFile << "Results Vector: ";
        for (auto vn: resultsVector)
        {
            vn->printRaw(strlenSampleFile);
            strlenSampleFile << ", ";
        }
        strlenSampleFile << std::endl << "********************************" << std::endl;
    }
    // verify that we have all we need for a completed transform
    if (resultVn == nullptr)
    {
        ghidra::pLogger->info("Unable to find resultVn, abandon strlen transform");
        ghidra::pLogger->flush();
        return TRANSFORM_ROLLED_BACK;
    }
    if (epiType == STREND)
    {
        ghidra::pLogger->warn("Vector string end method not implemented, abandon transform");
        ghidra::pLogger->flush();
        return TRANSFORM_ROLLED_BACK;
    }
    if (ghidra::trace)
    {
        resultVn->printRaw(ss);
        ghidra::pLogger->trace("\tSelecting as the result Varnode {0:s}", ss.str());
        ss.str("");
    }
    result = resultVn->getDef();

    if (sourceVn == nullptr)
    {
        ghidra::pLogger->warn("Failed to locate the strlen source operand - abandon transform");
        ghidra::pLogger->flush();
        return TRANSFORM_ROLLED_BACK;
    }
    if (ghidra::trace)
    {
        sourceVn->printRaw(ss);
        ghidra::pLogger->trace("\tSelecting as the source Varnode {0:s}", ss.str());
        ss.str("");
    }
    // a loop scratch register might be tentatively assigned to a later function call
    if (loopModel.unresolvedDependencies(result))
    {
        ghidra::pLogger->warn("Unable to complete transform due to one or more references to a loop-local Varnode");
        ghidra::pLogger->flush();
        return TRANSFORM_ROLLED_BACK;
    }
    // make sure vector_strlen is registered
    data.getArch()->userops.registerBuiltin(VECTOR_STRLEN);

    // Note: after this point pcode changes are irreversible

    // create a new Pcodeop with two varnode input parameters and one output varnode
    ghidra::PcodeOp *newVectorOp = data.newOp(2, loopBlock->getStop());
    data.opSetOpcode(newVectorOp, ghidra::CPUI_CALLOTHER);
    data.opSetInput(newVectorOp, data.newConstant(4, VECTOR_STRLEN), 0);
    data.opSetInput(newVectorOp, loopModel.vSourceOperands[0]->pExternal, 1);
    ghidra::Varnode* vectorResultVarnode = data.newVarnodeOut(resultVn->getSize(), resultVn->getAddr(), newVectorOp);
    if (ghidra::trace)
    {
        newVectorOp->printRaw(ss);
        ghidra::pLogger->trace("\tInserting a new vector operation\n\t\t{0:s}", ss.str());
        ss.str("");
    }
    data.opInsertEnd(newVectorOp, loopBlock);
    if (ghidra::trace) ghidra::inspector->log("Vector loop block after inserting vector_strlen is", loopBlock);
    // replace old result with new result
    std::vector<ghidra::PcodeOp*> resultSet = std::vector(resultVn->beginDescend(), resultVn->endDescend());
    for (auto op: resultSet)
    {
        ghidra::pLogger->trace("Examining dependency at 0x{0:x}:{1:x}", op->getAddr().getOffset(), op->getTime());
        for (int i = 0; i < op->numInput(); i++)
        {
            if (op->getIn(i) == resultVn)
            {
                ghidra::pLogger->trace("Replacing result varnode from slot {0:d} of op at 0x{1:x}", i, op->getAddr().getOffset());
                data.opUnsetInput(op, i);
                data.opSetInput(op, vectorResultVarnode, i);
            }
        }
    }
    // Delete enough common dependencies to make other Varnodes unused
    ghidra::PcodeOp* modifiableResult = const_cast<ghidra::PcodeOp*>(result);
    opsToDelete.push_back(modifiableResult);
    std::copy(std::begin(loopModel.loopOps), std::end(loopModel.loopOps),
        std::back_inserter(opsToDelete));
    std::copy(std::begin(loopModel.phiNodesAffectedByLoop), std::end(loopModel.phiNodesAffectedByLoop),
        std::back_inserter(opsToDelete));
    ghidra::BlockBasic* epilogBlock = modifiableResult->getParent();
    functionEditor.simplifyBlocks(opsToDelete, loopBlock, epilogBlock, &loopModel.relatedBlocks);
    ghidra::pLogger->flush();
    return TRANSFORM_COMPLETED;
}

bool VectorMatcher::isStrcmp()
{
    bool match =
        (loopModel.loopFlags == RISCV_VEC_INSN_FAULT_ONLY_FIRST) && // vector fault only first load
        loopModel.simpleFlowStructure &&            // no other  branches or calls
        (loopModel.vectorOps.size() == 7) &&        // vset, vload, vseq, vfirst
        (loopModel.otherScalarOps.size() == 0) &&   // no other ghidra pcodeops
        (loopModel.scalarOps.size() == 4) &&        // expected pointer and counter arithmetic
        (loopModel.vLogicalOps.size() == 2) &&      // vmor, vfirst
        (loopModel.vComparisonOps.size() == 2) &&   // vmsne, vmseq
        (loopModel.unhandledVectorOps.size() == 0) &&   // no unhandled vector instructions
        (loopModel.otherUserPcodes.size() == 0) &&  // no other CALL_OTHER
        (loopModel.vSourceOperands.size() == 2);  // two recognized source operands
    return match;
}

int VectorMatcher::transformStrcmp()
{
    std::stringstream ss;
    std::vector<ghidra::PcodeOp*> opsToDelete;
    ghidra::Varnode* firstArg = nullptr;  // the first argument to the vector_strcmp call
    ghidra::Varnode* secondArg = nullptr; // the second argument to the vector_strcmp call
    if (ghidra::info)
        ghidra::inspector->log("before strcmp transform, ", loopBlock);
    // Step 1: find the intersection of the two source operands pointer dependency set.
    // They should intersect twice - once in the loop termination's comparison condition, which we want to ignore,
    // and once again in the final result

    VectorEpilogProcessor epiProc(data, loopModel);
    std::set<ghidra::Varnode*> stopSet;
    stopSet.insert(loopModel.comparisonVarnode);
    epiProc.setStopSet(stopSet);
    // The result Varnode can be either a register varnode or an internal, temporary varnode
    epiProc.setResultFilter(VectorEpilogProcessor::ResultFilter::ANY_VARNODE);
    std::vector<ghidra::Varnode*> resultsVector;
    epiProc.getIntersectionVector(resultsVector,
        loopModel.vSourceOperands[0]->pRegister,
        loopModel.vSourceOperands[1]->pRegister);
    if ((resultsVector.size() == 0) || (resultsVector[0] == nullptr))
    {
        ghidra::pLogger->info("Unable to find resultVn, abandon strcmp transform");
        ghidra::pLogger->flush();
        return TRANSFORM_ROLLED_BACK;
    }
    ghidra::Varnode* resultVn = resultsVector[0];
    ghidra::PcodeOp* result = resultVn->getDef();
    bool comparisonInverted = false;
    result->printRaw(ss);
    ghidra::pLogger->info("strcmp result operation located: {0:s}", ss.str());
    ss.str("");
    // Now we need to resolve the ordering of the two arguments and what kind of comparison op
    // merges the result into the calling code
    firstArg = loopModel.vSourceOperands[0]->pExternal;
    secondArg = loopModel.vSourceOperands[1]->pExternal;
    // The result opcode tells us whether this is an ordering comparison or an equality
    // comparison.
    switch(result->code())
    {
        case ghidra::CPUI_INT_ADD:
            // An addition op may be part of a negate-add sequence, which should
            // be fixed by another Rule in another pass
            ghidra::pLogger->info("strcmp result is addition, try in another pass");
            ghidra::pLogger->flush();
            return TRANSFORM_ROLLED_BACK;
        case ghidra::CPUI_INT_SUB:
            // This is an ordering comparison, for instance string::operator<
            break;
        case ghidra::CPUI_CBRANCH:
            // This is a comparison already embedded in an unrelated branch
            ghidra::pLogger->warn("strcmp result is embedded in a branch statement - not implemented");
            ghidra::pLogger->flush();
            return TRANSFORM_ROLLED_BACK;
        case ghidra::CPUI_INT_EQUAL:
            comparisonInverted = false;
            break;
        case ghidra::CPUI_INT_NOTEQUAL:
            comparisonInverted = true;
            break;
        default:
            ghidra::pLogger->info("strcmp result is unrecognized, abandon transform");
            ghidra::pLogger->flush();
            return TRANSFORM_ROLLED_BACK;
    }
    if (loopModel.unresolvedDependencies(result))
    {
        ghidra::pLogger->warn("Unable to complete transform due to one or more references to a loop-local Varnode");
        ghidra::pLogger->flush();
        return TRANSFORM_ROLLED_BACK;
    }
    // create a new Pcodeop with three varnode input parameters and one output varnode
    ghidra::PcodeOp *newVectorOp = data.newOp(3, loopBlock->getStop());
    data.opSetOpcode(newVectorOp, ghidra::CPUI_CALLOTHER);
    data.getArch()->userops.registerBuiltin(VECTOR_STRCMP);
    data.opSetInput(newVectorOp, data.newConstant(4, VECTOR_STRCMP), 0);
    data.opSetInput(newVectorOp, firstArg, 1);
    data.opSetInput(newVectorOp, secondArg, 2);
    ghidra::Varnode* vectorResultVarnode = data.newVarnodeOut(resultVn->getSize(), resultVn->getAddr(), newVectorOp);
    // generate the inverse result varnode
    ghidra::PcodeOp* invertResultOp = data.newOp(1, vectorResultVarnode->getAddr());
    data.opSetOpcode(invertResultOp, ghidra::CPUI_BOOL_NEGATE);
    data.opSetInput(invertResultOp, vectorResultVarnode, 0);
    ghidra::Varnode* invertResultVn = data.newVarnodeOut(vectorResultVarnode->getSize(), vectorResultVarnode->getAddr(), invertResultOp);
    // log the pending transform
    resultVn->printRaw(ss);
    ss << " = ";
    ss << "vector_strcmp(";
    if (firstArg != nullptr)
        firstArg->printRaw(ss);
    else
        ss << "???";
    ss << ", ";
    if (secondArg != nullptr)
        secondArg->printRaw(ss);
    else
        ss << "???";
    ss << ")";
    ghidra::pLogger->trace("Preparing transform: {0:s}", ss.str());
    ss.str("");
    if (ghidra::trace)
    {
        newVectorOp->printRaw(ss);
        ghidra::pLogger->trace("\tInserting a new vector operation\n\t\t{0:s}", ss.str());
        ss.str("");
    }
    data.opInsertEnd(newVectorOp, loopBlock);
    data.opInsertAfter(invertResultOp, newVectorOp);
    if (ghidra::trace) ghidra::inspector->log( "Vector loop block after inserting vector_strcmp", loopBlock);
    // replace old result with new result
    std::vector<ghidra::PcodeOp*> resultSet = std::vector(resultVn->beginDescend(), resultVn->endDescend());
    for (auto op: resultSet)
    {
        ghidra::pLogger->trace("Examining dependency at 0x{0:x}:{1:x}", op->getAddr().getOffset(), op->getTime());
        for (int i = 0; i < op->numInput(); i++)
        {
            if (op->getIn(i) == resultVn)
            {
                ghidra::pLogger->trace("Replacing result varnode from slot {0:d} of op at 0x{1:x}", i, op->getAddr().getOffset());
                op->printRaw(ss);
                ghidra::pLogger->trace("\tOp was {0:s}", ss.str());
                ss.str("");
                if ((op->code() == ghidra::CPUI_CBRANCH) && (!comparisonInverted))
                {
                    ghidra::pLogger->trace("\tResult evaluated in boolean context;  varnodes:");
                    for (int j = 0; j < op->numInput(); j++)
                    {
                        op->getIn(j)->printRaw(ss);
                        ghidra::pLogger->trace("\t\tSlot {0:d} is {1:s}", j, ss.str());
                        ss.str("");
                    }
                    data.opUnsetInput(op, i);
                    data.opSetInput(op, invertResultVn, i);
                    op->printRaw(ss);
                    ghidra::pLogger->trace("\tOp is now {0:s}", ss.str());
                    ss.str("");
                }
                else
                {
                    ghidra::pLogger->trace("\tResult evaluated in integer context; varnodes:");
                    for (int j = 0; j < op->numInput(); j++)
                    {
                        op->getIn(j)->printRaw(ss);
                        ghidra::pLogger->trace("\t\tSlot {0:d} is {1:s}", j, ss.str());
                        ss.str("");
                    }
                    data.opUnsetInput(op, i);
                    data.opSetInput(op, vectorResultVarnode, i);
                    op->printRaw(ss);
                    ghidra::pLogger->trace("\tOp is now {0:s}", ss.str());
                    ss.str("");
                }
            }
        }
    }
    // Delete enough common dependencies to make other Varnodes unused
    opsToDelete.push_back(result);
    std::copy(std::begin(loopModel.loopOps), std::end(loopModel.loopOps),
        std::back_inserter(opsToDelete));
    std::copy(std::begin(loopModel.phiNodesAffectedByLoop), std::end(loopModel.phiNodesAffectedByLoop),
        std::back_inserter(opsToDelete));
    // remove unused ops and absorb any unnecessary do .. while wrappers
    ghidra::BlockBasic* epilogBlock = result->getParent();
    functionEditor.simplifyBlocks(opsToDelete, loopBlock, epilogBlock, &loopModel.relatedBlocks);
    ghidra::pLogger->flush();
    return TRANSFORM_COMPLETED;
}
}