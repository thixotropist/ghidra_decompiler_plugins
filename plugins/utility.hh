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
PcodeOp* insertBuiltin(Funcdata& data, const Address& addr, intb builtinOpId, Varnode* param1, Varnode* param2, Varnode* param3);

/**
 * @brief Add a PcodeOp 
 * 
 * @param data 
 * @param addr 
 */
PcodeOp* insertBranchOp(Funcdata& data, const Address& insertionPoint, Address& destinationAddr);

/**
 * @brief Get the register name associated with a given Varnode
 */
void getRegisterName(const Varnode* vn, std::string* regname);

/**
 * @brief compare registers associated with two Varnodes
 */
bool sameRegister(const Varnode* a, const Varnode* b);
}

#endif /* UTILITY_HH_ */
