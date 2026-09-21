#ifndef USER_PCODE_HH_
#define USER_PCODE_HH_

/**
 * @file user_pcode.hh
 * @author thixotropist
 * @brief Model Ghidra userPcodeOp objects constructed from RISC-V ISA extension instructions
 * @date 2026-08-21
 *
 * @copyright Copyright (c) 2026
 *
 */
#include <string>
#include <vector>
#include <map>

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/type.hh"

namespace riscv_vector
{

/**
 * @page traits User PCode Traits
 * Basic instruction traits can be assigned to many instructions.
 * These traits can help identify common vector instruction sequences,
 * blocks, and loops.  Each userPcodeOp includes a bitfield holding the traits
 * relevant to that instruction.  Vector sequences, including simple loops, can
 * then hold a signature bitfield OR'ing the traits of interior vector instructions.
 * These signatures can then help identify feasible transforms.
 *
 * Note that the traits initially follow the groupings used in the RISC-V Vector
 * specification document.  The separation between logical and arithmetic operations
 * is tentative.
 */
static const uint64_t OP_IS_LOAD = 0x01LU;             ///<@brief memory is loaded to a vector register
static const uint64_t OP_IS_STORE = 0x02LU;            ///<@brief memory is stored from a vector register
static const uint64_t OP_IS_VSET = 0x04LU;             ///<@brief this is a vset* instruction
static const uint64_t OP_IS_IMMEDIATE = 0x08LU;        ///<@brief an operand is immediate
static const uint64_t OP_IS_MASK = 0x10LU;             ///<@brief a mask operation
static const uint64_t OP_IS_STRIDED = 0x20LU;          ///<@brief strided by more than one unit
static const uint64_t OP_IS_FAULT_ONLY_FIRST = 0x40LU; ///<@brief only the first element can cause an exception
static const uint64_t OP_IS_ORDERED = 0x80LU;          ///<@brief operations must occur in order
static const uint64_t OP_IS_INDEXED = 0x100LU;         ///<@brief addresses are indexed
static const uint64_t OP_IS_SEGMENTED = 0x200LU;       ///<@brief operations are segmented across vector registers
static const uint64_t OP_IS_WHOLE_REGISTER = 0x400LU;  ///<@brief operations apply to entire vector register
static const uint64_t OP_IS_INTEGER_COMPARISON = 0x800LU;  ///<@brief vector integer comparison
static const uint64_t OP_IS_BITWISE_LOGICAL = 0x1000LU; ///<@brief vector bitwise logical op
static const uint64_t OP_IS_MASK_COMPARISON = 0x2000LU; ///<@brief vector comparison with mask
static const uint64_t OP_IS_MASK_OTHER = 0x4000LU;      ///<@brief vector other mask opk
static const uint64_t OP_IS_INTEGER_ARITH = 0x8000LU;   ///<@brief vector integer math
static const uint64_t OP_IS_WIDENING_INTEGER_ARITH = 0x10000LU; ///<@brief vector widening integer math
static const uint64_t OP_IS_INTEGER_EXTENSION = 0x20000LU;  ///<@brief vector sign extension
static const uint64_t OP_IS_INTEGER_CARRY_ARITH = 0x40000LU; ///<@brief vector integer math with carry
static const uint64_t OP_IS_SINGLE_WIDTH_SHIFT = 0x80000LU; ///<@brief vector shift
static const uint64_t OP_IS_NARROWING_SHIFT_RIGHT = 0x100000LU;  ///<@brief vector narrowing shift right
static const uint64_t OP_IS_INTEGER_MINMAX = 0x200000LU;  ///<@brief vector integer minimum or maximum
static const uint64_t OP_IS_INTEGER_SINGLE_WIDTH_MULTIPLY = 0x400000LU; ///<@brief vector integer multiply
static const uint64_t OP_IS_INTEGER_SINGLE_WIDTH_DIVIDE = 0x800000LU; ///<@brief vector integer divide
static const uint64_t OP_IS_INTEGER_WIDENING_MULTIPLY = 0x1000000LU; ///<@brief vector widening integer multiply
static const uint64_t OP_IS_INTEGER_MULTIPLY_ADD = 0x2000000LU; ///<@brief vector integer multiply add
static const uint64_t OP_IS_WIDENING_INTEGER_MULTIPLY_ADD = 0x4000000LU; ///<@brief vector widening integer multiply add
static const uint64_t OP_IS_INTEGER_MERGE = 0x8000000LU; ///<@brief vector merge
static const uint64_t OP_IS_INTEGER_MOVE = 0x10000000LU;///<@brief vector register to register move
static const uint64_t OP_IS_FLOATING_POINT = 0x20000000LU; ///<brief vector floating point

/**
 * @brief Map the assembly instruction name to the Ghidra internal userPcodeOp id bound
 * during SLEIGH language processing.
 * @details The name field should match an instruction name as defined in the RISC-V vector specification,
 * with any '.' characters replaced with '_' characters.  The GhidraId field is a Ghidra integer
 * assigned dynamically and stable only across a given Ghidra invocation instance.
 */
extern std::map<std::string, ghidra::uintb> riscvNameToGhidraId;
/**
 * @brief Each Ghidra UserPcode can include context information that affects adjacent instructions.
 */
enum ContextTypes
{
    NULL_CONTEXT,   ///<@brief No extended context defined for this userPcodeOp
    VSET_CONTEXT    ///<@brief Context defined appropriate to a vsetvli or vsetivli instruction
};
/**
 * @brief OpContext holds instruction or userPcodeOp context information.
 * @details This context is initially defined for Vset operations, but may
 * need to be extended for other operations.
 */
class OpContext
{
  public:
    /// @brief what type of context is in use here?
    ContextTypes cType;
    /// @brief constructor
    /// @param cTypeParam identifies the context type
    explicit OpContext(ContextTypes cTypeParam) : cType(cTypeParam) {};
    /// @brief destructor
    virtual ~OpContext() = default;
    ///@brief get the vset element size - useful only in a vset context.
    virtual int getElementSize() {return 0;};
    ///@brief get the vset LMUL if >= 1 - useful only in a vset context
    virtual int getMultiplier() {return 0;};
    ///@brief true if this is a vset instruction and `tu` is requested.
    virtual bool getTailUnchanged() {return false;};
    ///@brief true if this is a vset instruction and `mu` is requested.
    virtual bool getMaskUnchanged() {return false;};
};
/**
 * @brief Vsetvli and vsetivli instructions set context that affects the execution
 * of subsequent instructions.
 */
class VsetContext : public OpContext
{
  public:
    int elementSize;  ///<@brief vector element size in bytes
    int multiplier;   ///<@brief LMUL if >= 1 else 1
    bool isTailUnchanged; ///<@brief true if `tu` context is set
    bool isMaskUnchanged; ///<@brief true if `mu` context is set
    ///@brief constructor
    VsetContext(int size, int mult, bool isTailUnchangedParam, bool isMaskUnchangedParam) :
        OpContext(VSET_CONTEXT),
        elementSize(size),
        multiplier(mult),   ///<@brief LMUL if >= 1, else 1
        isTailUnchanged(isTailUnchangedParam),
        isMaskUnchanged(isMaskUnchangedParam)
    {};
    ///@brief getter for elementSize
    virtual int getElementSize() override {return elementSize;};
    ///@brief getter for multiplier
    virtual int getMultiplier() override {return multiplier;};
    ///@brief getter for isTailUnchanged
    virtual bool getTailUnchanged() override {return isTailUnchanged;};
    ///@brief getter for isMaskUnchanged
    virtual bool getMaskUnchanged() override {return isMaskUnchanged;};
};

/**
 * @brief Descriptor for a single RISC-V vector instruction.
 * @details In this context 'vector instruction' includes pseudo instructions and some
 * leftover RVV 0.7 instruction mnemonics not considered part of the RVV 1.0 release.
 */
class RiscvUserPcode
{
  public:
    const std::string& asmOpcode;    ///<@brief the name of this opcode as it appears in SLEIGH semantics
    int ghidraOp;                    ///<@brief the index by which Ghidra identifies this User Pcode
    uint64_t traits;                 ///<@brief traits that help categorize this userPcode
    OpContext* context;              ///<@brief optional context available for user pcode ops
    RiscvUserPcode(const std::string& asmName, uint64_t traitsParam); ///<@brief constructor, no added context
    RiscvUserPcode(const std::string& asmName, uint64_t traitsParam, OpContext* contextParam); ///<@brief constructor with added context
    static void loadAsmOpcodes();    ///<@brief construct the riscvNameToPcodeMap from known instructions
    ///@brief Assign previously loaded objects the id used in the current Ghidra Architecture
    void assignGhidraId(ghidra::uintb id){
        ghidraOp = id;
    };
    /**
     * @brief Get the User Pcode object from a Ghidra PcodeOp
     * @param op The Ghidra internal PcodeOp
     * @return a RiscvUserPcode* describing the UserPcodeOp
     */
    static const RiscvUserPcode* getUserPcode(const ghidra::PcodeOp& op);
    /**
     * @brief destroy static components like maps
     */
    static void staticCleanup();
};
/// @brief map instruction name like 'vle8_v' to the UserPcodeOp descriptor
extern std::map<std::string, RiscvUserPcode*> riscvNameToPcodeMap;
/// @brief lookup a user pcode given Ghidra's sleigh index
///@todo Should the 'int' be changed to 'ghidra::uintb'?
extern std::map<int, riscv_vector::RiscvUserPcode*> riscvPcodeMap;
}
#endif /* USER_PCODE_HH_ */