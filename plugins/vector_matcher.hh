#ifndef VECTOR_MATCHER_HH_
#define VECTOR_MATCHER_HH_

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

namespace ghidra{
class VectorMatcher {
  public:
    /**
     * @brief Construct a new Vector Tree Match object, populating pcodeOpSelection
     * with PcodeOps potentially implementing a vector stanza or loop
     * @param data Function context
     * @param vsetOp A vsetvl instruction that initiates a loop to be matched
     */
    VectorMatcher(Funcdata& fData, PcodeOp* vsetOp);

    Funcdata& data;          /// Function context data
    bool loopFound;          /// does the block contain a loop?
    intb loopStartAddr;      /// location of the loop start or 0
    intb loopEndAddr;        /// location of the loop end or 0
    BlockBasic* loopBlock;   /// the parent block of the loop
    std::vector<PcodeOp*> phiNodesAffectedByLoop;  /// Phi or MULTIEQUAL opcodes referencing loop variables
    std::vector<PcodeOp*> otherUserPcodes; /// Other user pcodes found within the loop
    std::list<PcodeOp *> externalDependentOps; /// Pcodes outside of the loop dependent on varnodes inside the loop
    bool numElementsConstant; /// vsetOp is a vseti provides number of elements as a constant
    bool numElementsVariable; /// vsetOp is a vset and provides number of elements in a register
    bool foundSimpleComparison; /// an integer conditional expression found
    bool foundUnexpectedOp;  /// An unexpected pcode op was found
    bool foundOtherUserPcodes; /// An unexpected user pcode op was found
    bool simpleFlowStructure;/// There is at most one backwards conditional branch present
    bool simpleLoadStoreStructure; /// One vector load and one store instruction present
    bool vectorRegistersMatch; /// is the use of vector registers consistent?
    int numArithmeticOps;    /// the number of likely pointer arithmetic ops
    int multiplier;          /// vset multiplier factor if >= 1
    int elementSize;         /// number of bytes per vector element
    PcodeOp* vsetOp;         /// vset PcodeOp
    Varnode* vNumElem;       /// Varnode setting number of elements to process
    Varnode* vNumPerLoop;    /// Varnode giving the number of elements per loop
    Varnode* vLoad;          /// Varnode used by a vector load instruction
    Varnode* vLoadImm;       /// Varnode used by a vector load immediate instruction
    Varnode* vStore;         /// Varnode used by a vector store instruction
    const bool trace;        /// true if logger would process loglevel=trace
    const bool info;         /// true if logger would process loglevel=info
    /**
     * @brief Perform basic analysis and feature extraction
     */
    void analyze();
    /**
     * @brief is this selection a simple memcpy?
     */
    bool isMemcpy();
    /**
     * @brief transform the selection into a builtin_memcpy
     * @return int 1 if transform successful, 0 if no transform completed
     */
    int transform();
    /**
     * @brief Destroy the Vector Tree Match object
     */
    ~VectorMatcher();

    private:
  /**
   * @brief construct basic control flow data to determine
   * if this is a simple loop
   */
    void collect_control_flow_data();

    /**
     * @brief Collect other PcodeOps bound to the initial vset instruction
     * @details These Pcodes may include Phi nodes showing register heritage,
     * or cast operations.  We are especially interested in Phi Pcodes that
     * reference loop registers
     * 
     * @param vsetOp 
     */
    void collect_phi_nodes();

    /**
     * @brief Examine pcode ops within a loop to locate key vector operations.
     */
    void examine_loop_pcodeops();

    /**
     * @brief Follow Phi nodes into the loop to identify the role of loop registers
     * 
     */
    void collect_loop_registers();

    /**
     * @brief Remove dependencies on interior loop Varnodes
     * @return True if successful, False if no transform is known safe
     */
    bool removeExteriorDependencies();

    /**
     * @brief 
     * 
     * @param vn a Varnode reference
     * @return true if the pcode defining this VN lies inside our loop
     * @return false 
     */
    bool isDefinedInLoop(const Varnode* vn);

    /**
     * @brief Remove duplicate varnodes in a Phi opcode
     */
    void reducePhiNode(PcodeOp* op);
};
}
#endif /* VECTOR_MATCHER_HH_ */