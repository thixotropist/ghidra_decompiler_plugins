#ifndef __RULE_VECTOR_TRANSFORM_HH__
#define __RULE_VECTOR_TRANSFORM_HH__

#include <iostream>
#include <unordered_set>

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/type.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/action.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"

namespace riscv_vector
{
/**
 * @file rule_vector_transform.hh
 */
/**
 * @brief A Rule collecting individual vector instructions into vector_* function invocations
 */
class RuleVectorTransform : public ghidra::Rule
{
public:
    /**
     * @brief Construct a new Rule Vector Transform object
     *
     * @param g the name of an existing Ghidra rule group
     */
    explicit RuleVectorTransform(const std::string &g); ///< Constructor
    /**
     * @brief Allow the ActionDatabase to clone this rule
     *
     * @param grouplist
     * @return Rule*
     */
    virtual ghidra::Rule *clone(const ghidra::ActionGroupList &grouplist) const override;
    /**
     * @brief Register the Ghidra ops for which we want callbacks
     *
     * @param oplist
     */
    virtual void getOpList(std::vector<ghidra::uint4> &oplist) const override;
    /**
     * @brief the callback function telling us of a relevant Ghidra op
     * @param op the PcodeOp triggering this callback
     * @param data the Funcdata object of the enclosing function
     * @return 0 if no changes made, 1 if changes made
     */
    virtual ghidra::int4 applyOp(ghidra::PcodeOp *op, ghidra::Funcdata &data) override;
};
}
#endif /* __RULE_VECTOR_TRANSFORM_HH__ */
