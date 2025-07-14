
#include "utility.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"

namespace ghidra{

PcodeOp* insertBuiltin(Funcdata& data, const Address& addr, intb builtinOpId, Varnode* param1, Varnode* param2, Varnode* param3)
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
bool sameRegister(const Varnode* a, const Varnode* b)
{
    Address aAddr = a->getAddr();
    if (aAddr.isInvalid()) return false;
    Address bAddr = b->getAddr();
    if (bAddr.isInvalid()) return false;
    if ((aAddr.getSpace() != registerAddrSpace) || (bAddr.getSpace() != registerAddrSpace)) return false;
    return aAddr.getOffset() == bAddr.getOffset();
}
}
