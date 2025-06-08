#ifndef VECTOR_MATCHER_HH_
#define VECTOR_MATCHER_HH_

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

namespace ghidra{

/**
 * @brief Phi or Multiequal nodes merge two register histories
 */
struct PhiNode {
  public:
    intb registerOffset;            /// identifies the associated register
    std::vector<Varnode*> varnodes; /// up to three varnodes

    PhiNode(intb reg, Varnode* v1, Varnode* v2, Varnode* v3);
};

/**
 * @brief Methods that analyze a sequence of PcodeOps to match
 * against common patterns.
 */
class VectorMatcher {
  public:
    /**
     * @brief ordering relation for PcodeOp* based on Address
     * @details comparison is first on Address then on SeqNum
     * @param a first of two PcodeOp* objects to compare
     * @param b second of two PcodeOp* objects to compare
     * @return true if address of a appears before address of b
     */
    class PcodeOpComparator {
      public:
        bool operator()(const PcodeOp* a, const PcodeOp* b) const
        {
            if (a->getAddr() == b->getAddr())
                return (a->getSeqNum() < b->getSeqNum());
            return (a->getAddr() < b->getAddr());
        }
    };
    static const int MAX_DEPENDENTS = 15;
    /**
     * @brief set of PcodeOps selected as possible loop transform candidates,
     * sorted with increasing Address and SeqNum
     */
    std::set<PcodeOp*, PcodeOpComparator> pcodeOpSelection;
    /**
     * @brief set of PcodeOps selected as possible external dependencies to be trimmed,
     * sorted with increasing Address and SeqNum
     */
    std::set<PcodeOp*, PcodeOpComparator> pcodeOpDependencies;

    /**
     * @brief Construct a new Vector Tree Match object, populating pcodeOpSelection
     * with PcodeOps potentially implementing a vector stanza or loop
     * @param data Function context
     * @param vsetOp A vsetvl instruction that initiates a loop to be matched
     */
    VectorMatcher(Funcdata& fData, PcodeOp* vsetOp);

    Funcdata& data;          /// Function context data
    bool loopFound;          /// does pcodeOpSelection contain a loop?
    intb loopStartAddr;      /// location of the loop start or 0
    intb loopEndAddr;        /// location of the loop end or 0
    BlockBasic* loopBlock;   /// the parent block of the loop
    std::vector<PcodeOp*> phiNodesAffectedByLoop;  /// Phi or MULTIEQUAL opcodes referencing loop variables
    std::vector<PcodeOp*> otherUserPcodes; /// Other user pcodes found within the loop
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
    Varnode* vLoadVn;        /// Varnode used by a vector load
    Varnode* vLoadImmVn;     /// Varnode used by a vector load immediate
    Varnode* vStoreVn;       /// Varnode used by a vector store
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
     * 
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
};
}
#endif /* VECTOR_MATCHER_HH_ */