/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __RULE_VECTOR_TRANSFORM_HH__
#define __RULE_VECTOR_TRANSFORM_HH__

#include <iostream>
#include <unordered_set>

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh"

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