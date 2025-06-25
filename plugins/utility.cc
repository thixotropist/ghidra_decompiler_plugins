
#include "utility.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"

namespace ghidra{

PcodeOp* insertBuiltin(Funcdata& data, PcodeOp& op, intb builtinOpId, Varnode* param1, Varnode* param2, Varnode* param3)
{
    // make sure this builtin is registered
    data.getArch()->userops.registerBuiltin(builtinOpId);
    PcodeOp *newOp = data.newOp(4,op.getAddr());
    data.opSetOpcode(newOp, CPUI_CALLOTHER);
    data.opSetInput(newOp, data.newConstant(4, builtinOpId), 0);
    data.opSetInput(newOp, param1, 1);
    data.opSetInput(newOp, param2, 2);
    data.opSetInput(newOp, param3, 3);
    return newOp;
}
void getRegisterName(const Varnode* vn, std::string* regName)
{
    AddrSpace* spc = arch->getSpaceByName("register");
    const Translate *trans = spc->getTrans();
    *regName = trans->getRegisterName(spc, vn->getAddr().getOffset(), 4);
}
bool sameRegister(const Varnode* a, const Varnode* b)
{
    Address aAddr = a->getAddr();
    Address bAddr = b->getAddr();
    AddrSpace* spc = arch->getSpaceByName("register");
    if (!(aAddr.getSpace() == spc) || !(bAddr.getSpace() == spc)) return false;
    return aAddr.getOffset() == bAddr.getOffset();
}
}
