#ifndef UTILITY_HH_
#define UTILITY_HH_
#include <string>
#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh"

#include "riscv.hh"

namespace ghidra{
/**
 * @brief Introduce an experimental rule to transform vector
 * sequences into vector_memcpy or vector_memset calls
 */
PcodeOp* insertBuiltin(Funcdata& data, PcodeOp& op, intb builtinOpId, Varnode* param1, Varnode* param2, Varnode* param3);

/**
 * @brief Get the register name associated with a given Varnode
 */
void getRegisterName(const Varnode* vn, std::string* regname);
}

#endif /* UTILITY_HH_ */