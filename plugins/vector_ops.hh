/**
 * @file vector_ops.hh
 * @author thixotropist
 * @brief Model the RISC-V assembly elements found in vector operands
 * @date 2025-10-07
 * @copyright Copyright (c) 2025
 */

#ifndef VECTOR_OPS_HH
#define VECTOR_OPS_HH

#include <set>
#include <vector>
#include "spdlog/spdlog.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "riscv.hh"

namespace riscv_vector{

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
        readModifyWrite, ///< read and modify some or all elements, then store
        constant,    ///< load a vector register with all constants
        indexer,     ///< load a vector register with (0, 1, 2, 3, ...) or similar
        other
    };
    /// @brief Provide string names for enum types during trace
    /// @brief initialize static objects once
    static void static_init();
    OperandType opType;              ///< The role for this operand
    ghidra::Varnode* base;           ///< Base address for this stripe
    ghidra::Varnode* vRegister;      ///< identify the vector result Varnode
    ghidra::Varnode* pRegister;      ///< identify the pointer Varnode within the loop
    ghidra::Varnode* pExternal;      ///< the vector address Varnode given to the loop
    ghidra::intb vector_register;    ///< vector register holding the values
    ghidra::intb pointer_register;   ///< scalar register holding the current pointer
    std::vector<ghidra::PcodeOp*> incrementOps;  ///< sequence of PcodeOps incrementing the pointer register
    int elementLength;               ///< element size in bytes
    /**
     * @brief Constructor
     * @param t The identified type of this new operand
     */
    explicit VectorOperand(OperandType t) :
      opType(t),
      base(nullptr),
      vRegister(nullptr),
      pRegister(nullptr),
      pExternal(nullptr),
      vector_register(0),
      pointer_register(0),
      elementLength(0) {}
    ~VectorOperand();                    ///< destructor
};

enum OperationType      ///< Scalar and Vector operations fall into several categories
{
  unknown,                 ///< not yet recognized
  copy,                    ///< copy
  load,                    ///< load
  addition,                ///< add to register
  pointerAddition,        ///< add to pointer register
  subtraction,             ///< subtract from register
  multiplication,          ///< multiplication
  twosComplement,         ///< twos complement
  comparison,              ///< various comparison operations
  conditionalBranch,      ///< conditional branch
  vectorSetup,             ///< vsetvli*
  vectorLoad,              ///< vector load from memory
  vectorLoadFF,            ///< vector load fail on first
  vectorStore,             ///< vector store to memory
  vectorToVector,          ///< vector operand to vector result
  vectorImmediateToVector, ///< vector and scalar immediate operands to vector result
  vectorPairToVector,      ///< two vector operands to a vector result
  vectorToScalar           ///< vector operand to scalar result
};

/**
 * @brief Vector operations (including load or store) transform a vector operand
 * into a vector or scalar result.
 */
class VectorOperation
{
  public:

    OperationType type;      ///< the OperationType for this operation.
    ghidra::PcodeOp* op;     ///< the original Ghidra PcodeOp
    ghidra::Varnode* result;///< the result of this operation
    ghidra::Varnode* arg0;  ///< the first argument of this operation
    ghidra::Varnode* arg1;  ///< the second argument of this operation, or null
    ghidra::Varnode* arg2;  ///< the third argument of this operation, or null
    VectorOperation(OperationType typeParam, ghidra::PcodeOp* opParam);  ///< Constructor
    static void static_init(); ///< initialize static objects once on initialization
};

/**
 * @brief Scalar operations include counter increments, pointer increments, and comparisons
 */
class ScalarOperation
{
  public:
    OperationType type;   ///< generic operation type
    ghidra::PcodeOp* op;     ///< the original Ghidra PcodeOp
    ghidra::Varnode* result; ///< the register adjusted in this operation, identified by its Ghidra ID
    ghidra::Varnode* arg0;  ///< the first argument of this operation
    ghidra::Varnode* arg1;  ///< the second argument of this operation, or null
    ghidra::Varnode* arg2;  ///< the third argument of this operation, or null
    ghidra::OpCode opcode; ///< the Ghidra operation code
    //std::vector<ghidra::Varnode*> arguments;  ///< increment or decrement value
    ScalarOperation(OperationType typeParam, ghidra::PcodeOp* opParam); ///< Constructor
};

/**
 * @brief Model a series of vector operations not within or associated with a loop,
 * most commonly a vector load/store combination.
 * @details This class provides survey, matching, and transformation code within the
 * constructor
 */
class VectorSeries
{
  public:
    ghidra::Funcdata& data; ///< summary data for the enclosing function
    ghidra::int4 numBytes; ///< number of bytes implied by the vsetivli trigger
    ghidra::BlockBasic* currentBlock; ///< the BasicBlock holding the vsetivli trigger
    std::vector<ghidra::PcodeOp *> loadSet; ///< vector load instructions found in the current block controlled by the first vsetivli
    /**
     * @brief Construct a vector series matcher, triggered by a vsetivli instruction
     * @param firstOp the Ghidra CALLOTHER invoking the vsetivli instruction
     * @param data Ghidra's accumulated context of the function being decompiled
     * @param vsetInfo information decoded from the invoking vsetivli instruction
     */
    VectorSeries(ghidra::PcodeOp* firstOp, ghidra::Funcdata& data, const RiscvUserPcode* vsetInfo);
    /// @brief match any simple series with fixed sizes like memset or memcpy
    /// @return ghidra::RETURN_TRANSFORM_PERFORMED if the function was changed
    int match();
};

/**
 * @brief Model a vector loop iterating over a variable number of elements
 */
class VectorLoop
{
  public:
    /// @brief @brief Lambda expressions used to process user pcode operators
    using userPcodeOpHandler = std::function<void(VectorLoop& loop, int ghidraOp, ghidra::PcodeOp* op)>;

    static const uint32_t TERMINATES_ON_COUNTDOWN = 0x00000001;   ///< This loop counts down to zero
    static const uint32_t TERMINATES_ON_POINTER_TEST = 0x00000002;///< This loop exits on pointer test
    static const uint32_t TERMINATES_ON_DATA_TEST = 0x00000004;   ///< This loop exits on data element test
    uint32_t terminationConditionFlags;  ///< collect tests controlling the termination of this loop
    enum TerminationCondition    ///< What kind of conditional expression(s) terminate this loop?
    {
      countDown,                 ///< An integer count of the number of elements left to process
      pointerTest,               ///< Incrementing or decrementing a pointer until it reaches the end of an array
      dataTest                   ///< A test against a data element read
    };

    /**
    * @brief the generic type of this vector function
    */
    enum fType {
        memcpy,           ///< similar to the stdlib memcpy
        memset,           ///< similar to the stdlib memset
        strlen,           ///< similar to the stdlib strlen
        transform,        ///< apply a scalar function to each element of a vector
        reduce,           ///< reduce a vector to a scalar
        innerProduct,     ///< inner product between two vectors
        unknown,          ///< unrecognized type
        other             ///< generic type not yet established
    };
    fType typ;             ///< this function type
    std::string name;      ///< display name
    // collect features we can use to identify matching transforms
    uint loopFlags;        ///< aggregated instruction flags found within the loop
    bool loopFound;        ///< was a simple loop found?
    ghidra::Funcdata& data;  ///< The ghidra function data top level information
    ghidra::PcodeOp* vsetOp; ///< The vsetvli or vsetivli pcode op found at the beginning of the loop
    ghidra::AddrSpace* codeSpace;   ///< The code address space containing the loop
    ghidra::intb firstAddr; ///< the first RAM address of this loop
    ghidra::intb lastAddr; ///< the last RAM address of this loop
    ghidra::BlockBasic* loopBlock;   ///< the parent block of the loop
    std::list<ghidra::FlowBlock*> prologBlocks; ///< Blocks which flow into loopBlock
    ghidra::Varnode* terminationVarnode; ///< boolean Varnode - if true, jump to start of the loop
    ghidra::PcodeOp* terminationControl; ///< variable tested to terminate the loop
    std::vector<ghidra::PcodeOp*> phiNodesAffectedByLoop;  ///< Phi or MULTIEQUAL opcodes referencing loop variables
    ghidra::OpCode comparisonOp; ///< Ghidra opcode for an integer comparison test
    bool simpleFlowStructure; ///< is this a simple loop?
    std::vector<ghidra::PcodeOp*> otherUserPcodes; ///< Other user pcodes found within the loop
    std::vector<VectorOperation*> vectorOps; ///< ordered vector operations with handlers assigned found within this loop
    std::vector<VectorOperation*> otherVectorOps; ///< ordered vector operations without handlers assigned found within this loop
    std::vector<ScalarOperation*> scalarOps; ///< ordered non-vector operations with handlers assigned collected within this loop
    std::vector<ScalarOperation*> otherScalarOps; ///< ordered non-vector operations with handlers assigned collected within this loop
    std::vector<const ghidra::PcodeOp*> epilogPcodes; ///< vector operations found in the loop epilog
    std::vector<VectorOperation*> vLoadOps;    ///< vector load operations found
    std::vector<VectorOperation*> vStoreOps;   ///< vector store operations found
    std::vector<ScalarOperation*> sIntegerOps; ///< scalar integer operations found
    std::vector<ScalarOperation*> sComparisonOps; ///< scalar comparison operations found
    std::vector<VectorOperand*> vSourceOperands; ///< vector source operands and their loop context
    std::vector<VectorOperand*> vDestinationOperands; ///< vector destination operands and their loop context
    ghidra::Varnode* numElements;  ///< Varnode tracking the number of elements remaining to be processed
    /**
     * @brief Construct a new Vector Function object to hold model parameters
     * @param dataParam The Ghidra function data top level object
     * @param traceParam True if the current log level includes tracing
     */
    VectorLoop(ghidra::Funcdata& dataParam, const bool traceParam);
    /**
     * @brief Destroy the Vector Function object
     */
    ~VectorLoop();
    /**
     * @brief Is this Varnode defined within (generated within) the current loop?
     * @param vn a Varnode reference
     * @return true if the pcode defining this VN lies inside our loop
     */
    bool isDefinedInLoop(const ghidra::Varnode* vn);
    /**
     * @brief perform one-time static initialization
     */
    static void static_init();
    /**
     * @brief Analyze the loop to collect traits useful in matching and transforms
     * @param vsetOp The vsetvli or vsetivli instruction found at the top of the loop
     */
    void analyze(ghidra::PcodeOp* vsetOp);
    /**
     * @brief log this model to the current logfile
     */
    void log();
    /**
     * @brief Remove duplicate varnodes in a Phi opcode
     */
    void reducePhiNode(ghidra::PcodeOp* op);
    /**
     * @brief remove all PCodeOps from the loop, identifying external operand Varnodes
     * in the process.
     * @details Updates registered operands and condenses Phi nodes.
     * @returns True if successful, False if the transform should be aborted
     */
    bool absorbOps();
  private:

    int multiplier;                        ///< vset multiplier
    int elementSize;                       ///< vset element size
    ghidra::intb vlReg;                    ///< vector load destination register
    ghidra::intb vlAddrReg;                ///< vector load scalar pointer register
    ghidra::intb vlAddrIncrReg;            ///< vector load scalar pointer increment register
    ghidra::intb vsReg;                    ///< vector store source register
    ghidra::intb vsAddrReg;                ///< vector store scalar pointer register
    ghidra::intb vsAddrIncrReg;            ///< vector store scalar pointer increment register
    ghidra::intb elementCounterReg;        ///< loop element counter register
    bool trace; ///< is trace logging enabled?
    /**
     * @brief Invoke a vector instruction (user PcodeOp) handler to update the VectorLoop model.
     * @details This handler triggers on user PcodeOps when iterating through a vector loop.
     * Don't confuse it with a generic higher level vector operation.
     *
     * @param op The ghidra PcodeOp implementing the userPcodeOpHandler.
     */
    bool invokeVectorOpHandler(ghidra::PcodeOp* op);
    /**
    * @brief construct basic control flow data around a vset op to determine
    * if this is a simple loop
    */
    void examine_control_flow(ghidra::PcodeOp* vsetOp);
    /**
     * @brief Collect other PcodeOps bound to the initial vset instruction
     * @details These Pcodes may include Phi nodes showing register heritage,
     * or cast operations.  We are especially interested in Phi Pcodes that
     * reference loop registers
     */
    void collect_phi_nodes();
    /**
     * @brief Examine pcode ops within a loop to locate key vector operations.
     * @param loopBlock The Ghidra block containing the trigger vset instruction
     */
    void examine_loop_pcodeops(const ghidra::BlockBasic* loopBlock);
    /**
     * @brief Identify common loop elements like vector loads, vector stores, and element counters
     */
    void collect_common_elements();
    /**
     * @brief Identify key instructions following this loop, such
     * as might be needed for reduction algorithms.
     */
    void examine_loop_epilog();
    /**
     * @brief collect possible prolog blocks
     */
    void collect_prolog_blocks();
    /**
     * @brief Generate a summary report for this vector loop
     */
    void generateReport();
};
}
#endif /* VECTOR_OPS_HH */
