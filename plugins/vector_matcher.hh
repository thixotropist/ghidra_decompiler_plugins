#ifndef VECTOR_MATCHER_HH_
#define VECTOR_MATCHER_HH_

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

#include "inspector.hh"
#include "vector_ops.hh"
  /**
   * @file vector_matcher.hh
   */
namespace riscv_vector
{

/**
 * @brief VectorMatcher collects features extracted from sequences of vector instructions,
 * where those features can be later used to match against common patterns.
 */
class VectorMatcher {
  public:
    VectorLoop loopModel;  ///< Model the function being matched
    const int TRANSFORM_COMPLETED = 1;   ///< Return code on a completed transform
    const int TRANSFORM_ROLLED_BACK = 0; ///< Return code if a transform was aborted
    ghidra::Funcdata& data;          ///< Function context data
    ghidra::FunctionEditor functionEditor; ///< Tools to edit a function's structure
    ghidra::AddrSpace* codeSpace;    ///< The code address space containing the loop
    ghidra::Address nextInstructionAddress; ///< location at which we resume execution
    ghidra::BlockBasic* loopBlock;   ///< the parent block of the loop
    std::list<ghidra::PcodeOp *> externalDependentOps; ///< Pcodes outside of the loop dependent on varnodes inside the loop
    bool numElementsConstant; ///< vsetOp is a vseti provides number of elements as a constant
    bool numElementsVariable; ///< vsetOp is a vset and provides number of elements in a register
    bool vectorRegistersMatch; ///< is the use of vector registers consistent?
    int multiplier;          ///< vset multiplier factor if >= 1
    int elementSize;         ///< number of bytes per vector element
    ghidra::PcodeOp* vsetOp;         ///< vset PcodeOp
    ghidra::Varnode* vNumElem;       ///< Varnode setting number of elements to process
    ghidra::Varnode* vNumPerLoop;    ///< Varnode giving the number of elements per loop
    ghidra::Varnode* vLoad;          ///< Varnode used by a vector load instruction
    ghidra::Varnode* vLoadImm;       ///< Varnode used by a vector load immediate instruction
    ghidra::Varnode* vStore;         ///< Varnode used by a vector store instruction
    const bool trace;        ///< true if logger would process loglevel=trace
    const bool info;         ///< true if logger would process loglevel=info
    /**
     * @brief Construct a new VectorMatcher object, populating pcodeOpSelection with PcodeOps potentially implementing a vector stanza or loop
     * @param fData Function context
     * @param vsetOp A vsetvl or vsetvli instruction that initiates a loop to be matched
     */
    VectorMatcher(ghidra::Funcdata& fData, ghidra::PcodeOp* vsetOp);
    /**
     * @brief Destroy the Vector Tree Match object
     */
    ~VectorMatcher();
    /**
     * @brief is this selection a simple memcpy?
     */
    bool isMemcpy();
    /**
     * @brief is this selection a simple strlen?
     */
    bool isStrlen();
    /**
     * @brief is this selection a simple strcmp?
     */
    bool isStrcmp();
    /**
     * @brief transform the selection into a vector_memcpy
     * @return int 1 if transform successful, 0 if no transform completed
     */
    int transformMemcpy();
    /**
     * @brief transform the selection into a vector_strlen
     * @return int 1 if transform successful, 0 if no transform completed
     */
    int transformStrlen();
    /**
     * @brief transform the selection into a vector_strcmp
     * @return int 1 if transform successful, 0 if no transform completed
     */
    int transformStrcmp();
  private:
    /**
     * @brief Follow Phi nodes into the loop to identify the role of loop registers
     *
     */
    void collect_loop_registers();
  };
}
#endif /* VECTOR_MATCHER_HH_ */
