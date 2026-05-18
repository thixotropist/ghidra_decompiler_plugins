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

RuleCsrRemoveHeritage::RuleCsrRemoveHeritage(const std::string &g) :
    ghidra::Rule(g, 0, "csrRemoveHeritage") {}

ghidra::Rule* RuleCsrRemoveHeritage::clone(const ghidra::ActionGroupList &grouplist) const
{
    if (!grouplist.contains(getGroup())) {
        ghidra::pLogger->error("RuleCsrRemoveHeritage::clone failed for lack of a group");
        return (ghidra::Rule *)0;
    }
    ghidra::pLogger->trace("Prepared a new RuleCsrRemoveHeritage for Action database");
    ghidra::pLogger->flush();
    return new RuleCsrRemoveHeritage(getGroup());
}

void RuleCsrRemoveHeritage::getOpList(std::vector<ghidra::uint4> &oplist) const {
    oplist.push_back(ghidra::CPUI_CALLOTHER);
}

static std::set<ghidra::intb> functions_processed;
ghidra::int4 RuleCsrRemoveHeritage::applyOp(ghidra::PcodeOp *firstOp, ghidra::Funcdata &data)
{
    [[maybe_unused]] bool trace = ghidra::pLogger->should_log(spdlog::level::trace);
    // require one of several vset* instructions to begin this pattern,
    // adjusting the maximum number of pcode ops to examine
    const RiscvUserPcode* vsetInfo =
        RiscvUserPcode::getUserPcode(*firstOp);
    if (vsetInfo == nullptr) return ghidra::RETURN_NO_TRANSFORM;
    bool vsetImmediate = vsetInfo->isVseti;
    bool vsetRegister = vsetInfo->isVset;
    if (!(vsetImmediate || vsetRegister)) return ghidra::RETURN_NO_TRANSFORM;
    // we have a vsetivli or a vsetvli instruction
    ghidra::intb function_start = data.getAddress().getOffset();
    if (functions_processed.find(function_start) != functions_processed.end())
        return ghidra::RETURN_NO_TRANSFORM;
    functions_processed.insert(function_start);
    ActionPluginPrepare actPrep(ghidra::pLogger);
    actPrep.purgeCsrHeritage(data);
    return ghidra::RETURN_TRANSFORM_PERFORMED;
}

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
    // construct a VectorMatcher to start the loop analysis.
    VectorMatcher matcher(data, firstOp);
    ghidra::pLogger->flush();
    if (!matcher.loopModel.loopFound)
    {
        return ghidra::RETURN_NO_TRANSFORM;
    }
    ghidra::pLogger->trace("Testing the vector stanza for a vector_memcpy match");
    if (matcher.isMemcpy())
    {
        if (transformCountLoop >= TRANSFORM_LIMIT_LOOPS)
        {
            ghidra::pLogger->info("Ceasing transforms - loop limit of {0:d} reached",
                TRANSFORM_LIMIT_LOOPS);
            ghidra::pLogger->flush();
            if (ghidra::inspector->audit_block_graph)
            {
                std::ofstream outFile("/tmp/memcpy_blockgraph_audit.log");
                ghidra::inspector->auditBlockGraph(data, outFile);
                outFile.close();
            }
            return ghidra::RETURN_NO_TRANSFORM;
        }
        ++transformCountLoop;
        ghidra::pLogger->flush();
        if (ghidra::inspector->audit_varnodes)
        {
            std::ofstream outFile("/tmp/memcpy_varnode_audit.log");
            ghidra::inspector->auditVarnodes(data, outFile);
            outFile.close();
        }
        if (ghidra::inspector->audit_block_graph)
        {
            std::ofstream outFile("/tmp/memcpy_blockgraph_audit.log");
            ghidra::inspector->auditBlockGraph(data, outFile);
            outFile.close();
        }
        return matcher.transformMemcpy();
    }
    ghidra::pLogger->trace("Testing the vector stanza for a vector_strlen match");
    if (matcher.isStrlen())
    {
        if (transformCountLoop >= TRANSFORM_LIMIT_LOOPS)
        {
            ghidra::pLogger->flush();
            return ghidra::RETURN_NO_TRANSFORM;
        }
        ++transformCountLoop;
        ghidra::pLogger->flush();
        return matcher.transformStrlen();
    }
    ghidra::pLogger->trace("Testing the vector stanza for a vector_strcmp match");
    if (matcher.isStrcmp())
    {
        if (transformCountLoop >= TRANSFORM_LIMIT_LOOPS)
        {
            ghidra::pLogger->flush();
            return ghidra::RETURN_NO_TRANSFORM;
        }
        ++transformCountLoop;
        ghidra::pLogger->flush();
        return matcher.transformStrcmp();
    }
    ghidra::pLogger->trace("No matches found, returning");
    ghidra::pLogger->flush();
    return ghidra::RETURN_NO_TRANSFORM;
}
}
