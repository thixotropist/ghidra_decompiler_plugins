/**
 * @file vector_ops.hh
 * @author thixotropist
 * @brief Model the RISC-V assembly elements found in vector operands
 * @date 2025-10-07
 * @copyright Copyright (c) 2025
 */

#ifndef VECTOR_OPS_HH
#define VECTOR_OPS_HH

#include "Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include <vector>
#include "spdlog/spdlog.h"
#include "riscv.hh"

namespace riscv_vector{

/**
 * @brief A stripe or slice of a vector operand, usually a result of loop unrolling.
 */
class VectorStripe
{
  public:
    ghidra::Varnode* base;   ///< Base address for this stripe
    ghidra::intb vector_register;    ///< vector register holding the values
    ghidra::intb pointer_register;   ///< scalar register holding the current pointer
    std::vector<ghidra::PcodeOp*> incrementOps;  ///< sequence of PcodeOps incrementing the pointer register
    int elementLength;       ///< element size in bytes
    void setVregister(const ghidra::Varnode* const vn);  ///< identify the vector result register used
    void setBaseAddr(const ghidra::Varnode* const vn);   ///< identify the scalar pointer register used
};

/**
 * @brief VectorOperand collects Ghidra PcodeOps that might be generated during
 * loop vectorization.  They are similar to `std::vector<>` operands that might be found
 * in `std::transform(...)`, `std::reduce(...)`, or `std::inner_product(...)` operations.
 */
class VectorOperand
{
  public:
    /// @brief Vector Operands can be load or store or other
    enum OperandType {
        load,        ///< load a vector register from memory
        store,       ///< store a vector register to memory
        constant,    ///< load a vector register with all constants
        indexer,     ///< load a vector register with (0, 1, 2, 3, ...) or similar
        other
    };
    /// @brief Provide string names for enum types
    const std::vector<std::string> opTypeToString {
      "load", "store", "constant", "indexer", "other"
    };
    OperandType opType;                  ///< The role for this operand
    std::vector<VectorStripe*> stripes;  ///< One or more stripes manipulating the vector
    /**
     * @brief Constructor
     * @param t The identified type of this new operand
     */
    explicit VectorOperand(OperandType t) : opType(t) {}; ///< constructor
    ~VectorOperand();                    ///< destructor
};

/**
 * @brief Vector operations (other than load or store) transform a vector operand
 * into a vector or scalar result.
 */
class VectorOperation
{
  public:
    enum OperationType      ///< Vector operations fall into several categories
    {
      vectorToVector,       ///< vector operand to vector result
      vectorPairToVector,   ///< two vector operands to a vector result
      vectorToScalar        ///< vector operand to scalar result
    };
    OperationType typ;      ///< the OperationType for this operation.
};

/**
 * @brief Scalar operations within a vector loop are often pointer or counter increments or decrements
 */
class ScalarOperation
{
  public:
    ghidra::intb scalar_register; ///< the register adjusted in this operation
    ghidra::Varnode* adjustment;  ///< increment or decrement value
};

/**
 * @brief Model a generic vector function, such as those defined in std::
 * @todo Consider renaming this class from VectorFunction to VectorLoop, as it
 * primarily considers pcode only within a tight loop.
 */
class VectorFunction
{
  using Operation = std::function<void(int ghidraOp, const ghidra::PcodeOp* op)>;
  public:
    std::map<int, Operation> operations; ///< Map of loop instruction callbacks keyed by Ghidra opcode id
    /**
    * @brief the generic type of this vector function
    */
    enum fType {
        memcpy,
        memset,
        strlen,
        transform,
        reduce,
        innerProduct,
        unknown,
        other
    };
    /// @brief labels for logging fType values
    const std::vector<std::string> fTypeToString =
        {"memcpy", "memset", "strlen",  "transform",  "reduce",
            "innerProduct", "unknown", "other"};
    fType typ;             ///< this function type
    std::string name;      ///< display name
    // collect features we can use to identify matching transforms
    uint loopFlags;        ///< aggregated instruction flags found within the loop
    int numLoopVectorOps;  ///< number of vector operations found within the loop
    int numArithmeticOps;  ///< number of arithmetic pcodes found within the loop
    bool foundOtherUserPcodes; ///< are their unrecognized pcodes found within the loop?
    bool simpleFlowStructure; ///< is this a simple loop?
    bool foundSimpleComparison; ///< does this loop end with a simple comparison and conditional branch?
    bool foundUnexpectedOpcode;   /// unexpected user opcode found within the loop
    std::vector<ghidra::PcodeOp*> otherUserPcodes; ///< Other user pcodes found within the loop
    std::vector<VectorOperand*> operands; ///< unordered operands collected within this function
    /**
     * @brief Construct a new Vector Function object to hold model parameters
     */
    VectorFunction();
    /**
     * @brief Add a new vector load operand or slice
     * @param op The Vle* PcodeOp loading a vector register from memory
     */
    void addLoadOperand(const ghidra::PcodeOp* const op);
    /**
     * @brief Add a new vector store operand or slice
     * @param op The Vse* PcodeOp loading a vector register from memory
     */
    void addStoreOperand(const ghidra::PcodeOp* const op);
    /**
     * @brief Invoke a vector instruction (user PcodeOp) handler to update the VectorFunction model.
     * @details This handler triggers on user PcodeOps when iterating through a vector loop.
     * Don't confuse it with a generic higher level vector operation.
     *
     * @param op The ghidra PcodeOp implementing the Operation.
     */
    bool invokeVectorOpHandler(ghidra::PcodeOp* op);
    /**
     * @brief log this model to the current logfile
     */
    void log();
    /**
     * @brief Examine pcode ops within a loop to locate key vector operations.
     * @param loopBlock The Ghidra block containing the trigger vset instruction
     */
    void examine_loop_pcodeops(const ghidra::BlockBasic* loopBlock);
    /**
     * @brief Destroy the Vector Function object
     */
    ~VectorFunction();
};
}
#endif /* VECTOR_OPS_HH */
