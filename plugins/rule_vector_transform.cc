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

namespace riscv_vector {

RuleVectorTransform::RuleVectorTransform(const std::string &g) :
    ghidra::Rule(g, 0, "vectorTransforms") {}

ghidra::Rule* RuleVectorTransform::clone(const ghidra::ActionGroupList &grouplist) const
{
    if (!grouplist.contains(getGroup())) {
        ghidra::pLogger->error("RuleVectorTransform::clone failed for lack of a group");
        return (ghidra::Rule *)0;
    }
    ghidra::pLogger->trace("Prepared a new RuleVectorTransform for Action database");
    ghidra::pLogger->flush();
    return new RuleVectorTransform(getGroup());
}

void RuleVectorTransform::getOpList(std::vector<ghidra::uint4> &oplist) const {
    oplist.push_back(ghidra::CPUI_CALLOTHER);
}

ghidra::int4 RuleVectorTransform::applyOp(ghidra::PcodeOp *firstOp, ghidra::Funcdata &data) {
    [[maybe_unused]] bool trace = ghidra::pLogger->should_log(spdlog::level::trace);
    // require one of several vset* instructions to begin this pattern,
    // adjusting the maximum number of pcode ops to examine
    const RiscvUserPcode* vsetInfo =
        RiscvUserPcode::getUserPcode(*firstOp);
    if (vsetInfo == nullptr) return ghidra::RETURN_NO_TRANSFORM;
    // construct a VectorMatcher to start the analysis.
    VectorMatcher matcher(data, firstOp);
    bool vsetImmediate = vsetInfo->isVseti;
    bool vsetRegister = vsetInfo->isVset;
    if (!(vsetImmediate || vsetRegister)) return ghidra::RETURN_NO_TRANSFORM;
    // we have a vsetivli or a vsetvli instruction
    ghidra::pLogger->trace("Entering applyOp with a recognized vset* user pcode op at 0x{0:x}",
        firstOp->getAddr().getOffset());
    // If the firstOp is a vseti instruction, there is no loop and we can handle it locally
    if (vsetImmediate)
    {
        VectorSeries seriesMatcher(firstOp, data, vsetInfo);
        return seriesMatcher.match();
    }
    // Otherwise, this must be a vset and is likely a loop requiring much more processing
    ghidra::pLogger->trace("Testing the vector stanza for a vector_memcpy match");
    if (matcher.isMemcpy())
    {
        if (transformCountLoop >= TRANSFORM_LIMIT_LOOPS) return 0;
        ++transformCountLoop;
        return matcher.transformMemcpy();
    }
    ghidra::pLogger->trace("Testing the vector stanza for a vector_strlen match");
    if (matcher.isStrlen())
    {
        if (transformCountLoop >= TRANSFORM_LIMIT_LOOPS) return 0;
        ++transformCountLoop;
        return matcher.transformStrlen();
    }
    return ghidra::RETURN_NO_TRANSFORM;
}
}
