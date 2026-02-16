#ifndef FRAMEWORK_HH_
#define FRAMEWORK_HH_
#include <string>
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh"

#include "riscv.hh"

namespace ghidra{

/**
 * @file framework.hh
 * @brief Components available for all plugins
 */

extern std::shared_ptr<spdlog::logger> pLogger; ///< SPDLOG plugin logger

/**
 * @brief Insert a CALLOTHER pcodeop invoking a user-defined datatyped builtin op with three parameters and void output
 * @param data The overall Function data object
 * @param addr The Ghidra address (space and offset) at which to insert this pcodeop
 * @param builtinOpId The registered datatyped builtin op identifier
 * @param param1 The first parameter
 * @param param2 The second parameter
 * @param param3 The third parameter
 * @returns pointer to the new PcodeOp
 * @details This function prepares the new PcodeOp for insertion but does not itself do the insertion
 */
PcodeOp* insertVoidCallOther(Funcdata& data, const Address& addr, intb builtinOpId, Varnode* param1, Varnode* param2, Varnode* param3);

/**
 * @brief Add a Branch PcodeOp
 *
 * @param data The overall Function data object
 * @param insertionPoint The location for this new branch PcodeOp
 * @param destinationAddr The goto target for this new branch PcodeOp
 */
PcodeOp* insertBranchOp(Funcdata& data, const Address& insertionPoint, Address& destinationAddr);

/**
 * @brief Get the register name associated with a given Varnode
 * @param vn The Varnode to be inspected
 * @param regName pointer to the register name result
 */
void getRegisterName(const Varnode* vn, std::string* regName);

/**
 * @brief Get the register name associated with an offset in register space
 * @param offset The offset of a register in register space
 * @param regName pointer to the register name result
 */
void getRegisterName(intb offset, std::string* regName);

/**
 * @brief compare registers associated with two Varnodes
 * @param a first of two varnodes
 * @param b second of two varnodes
 * @returns true if these Varnodes are both in the register space and have the same offset
 */
bool sameRegister(const Varnode* a, const Varnode* b);

/**
 * @brief Methods to edit a Ghidra function's data
 *
 */
class FunctionEditor
{
  public:
    Funcdata& data; ///<@brief Ghidra function data
    ///@brief Editor methods operating on a Ghidra Function data object
    explicit FunctionEditor(Funcdata& dataParam) : data(dataParam) {};
    /**
     * @brief Given a BlockBasic, remove any enclosing empty do...while wrapper
     *
     * @param blk The BlockBasic presumably wrapped in an empty do...while
     */
    void removeDoWhileWrapperBlock(BlockBasic* blk);
    /**
     * @brief replace all references to oldBlock with a reference to newBlock.
     * @details This method includes all dependencies, including if branches and gotos
     * @param graph The BlockGraph object to be processed
     * @param oldBlock The block to be replaced
     * @param newBlock The replacement block
     */
    static void replaceBlock(const BlockGraph* graph, FlowBlock* oldBlock, FlowBlock* newBlock);
    /**
     * @brief Remove any PCodeOps for which the output Varnode has no descendents
     */
    void removeUnusedOps(FlowBlock* block);
};

/**
 * @brief Collect methods for editing a BlockGraph
 *
 */
class BlockGraphEditor {
  public:
    const BlockGraph& graph; ///<@brief The graph to be edited
    ///@brief Constructor
    explicit BlockGraphEditor(const BlockGraph& targetGraph) : graph(targetGraph) {};
    /**
     * @brief Collect subblocks and any goto targets from a given Blockgraph
     * @param list
     */
    void collectSubBlocks(std::vector<const FlowBlock*>& list) const;
};
}

#endif /* FRAMEWORK_HH_ */