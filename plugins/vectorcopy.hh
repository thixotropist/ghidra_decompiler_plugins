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
#ifndef __VECTORCOPY_HH__
#define __VECTORCOPY_HH__

#include <iostream>
#include <unordered_set>
#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh"
#include "vectorsequence.hh"

namespace ghidra{
class RuleVectorCopy : public Rule
{
public:
    explicit RuleVectorCopy(const string &g); ///< Constructor
    virtual Rule *clone(const ActionGroupList &grouplist) const override;
    virtual void getOpList(vector<uint4> &oplist) const override;
    virtual int4 applyOp(PcodeOp *op, Funcdata &data) override;

private:
    uintb op_vsetvli_e8m8tama;
    uintb op_vsetivli_e8m8tama;
    uintb op_vsetvli_e8m1tama;
    uintb op_vsetivli_e8m1tama;
    uintb op_vsetivli_e8mf2tama;
    uintb op_vsetivli_e8mf4tama;
    uintb op_vsetivli_e8mf8tama;
    uintb op_vle8_v;
    uintb op_vse8_v;
    FirstOp getFirstOp(uintb userop_index);
};
}
#endif /* __VECTORCOPY_HH__ */