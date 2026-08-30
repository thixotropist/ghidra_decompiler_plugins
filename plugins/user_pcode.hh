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

/**
 * @brief Model RISCV-V user PcodeOps implementing ISA extensions.
 */
namespace riscv_vector
{

/**
 * @brief Basic instruction traits can be assigned to many instructions
 */
static const uint64_t OP_IS_LOAD = 0x01LU;
static const uint64_t OP_IS_STORE = 0x02LU;
static const uint64_t OP_IS_VSET = 0x04LU;
static const uint64_t OP_IS_IMMEDIATE = 0x08LU;
static const uint64_t OP_IS_MASK = 0x10LU;
static const uint64_t OP_IS_STRIDED = 0x20LU;
static const uint64_t OP_IS_FAULT_ONLY_FIRST = 0x40LU;
static const uint64_t OP_IS_ORDERED = 0x80LU;
static const uint64_t OP_IS_INDEXED = 0x100LU;
static const uint64_t OP_IS_SEGMENTED = 0x200LU;
static const uint64_t OP_IS_WHOLE_REGISTER = 0x400LU;
static const uint64_t OP_IS_INTEGER_COMPARISON = 0x800LU;
static const uint64_t OP_IS_BITWISE_LOGICAL = 0x1000LU;
static const uint64_t OP_IS_MASK_COMPARISON = 0x2000LU;
static const uint64_t OP_IS_MASK_OTHER = 0x4000LU;
static const uint64_t OP_IS_INTEGER_ARITH = 0x8000LU;
static const uint64_t OP_IS_WIDENING_INTEGER_ARITH = 0x10000LU;
static const uint64_t OP_IS_INTEGER_EXTENSION = 0x20000LU;
static const uint64_t OP_IS_INTEGER_CARRY_ARITH = 0x40000LU;
static const uint64_t OP_IS_SINGLE_WIDTH_SHIFT = 0x80000LU;
static const uint64_t OP_IS_NARROWING_SHIFT_RIGHT = 0x100000LU;
static const uint64_t OP_IS_INTEGER_MINMAX = 0x200000LU;
static const uint64_t OP_IS_INTEGER_SINGLE_WIDTH_MULTIPLY = 0x400000LU;
static const uint64_t OP_IS_INTEGER_SINGLE_WIDTH_DIVIDE = 0x800000LU;
static const uint64_t OP_IS_INTEGER_WIDENING_MULTIPLY = 0x1000000LU;
static const uint64_t OP_IS_INTEGER_MULTIPLY_ADD = 0x2000000LU;
static const uint64_t OP_IS_WIDENING_INTEGER_MULTIPLY_ADD = 0x4000000LU;
static const uint64_t OP_IS_INTEGER_MERGE = 0x8000000LU;
static const uint64_t OP_IS_INTEGER_MOVE = 0x10000000LU;

/**
 * @brief map the assembly instruction name to the Ghidra internal userPcodeOp id bound
 * during SLEIGH language processing.
 */
extern std::map<std::string, ghidra::uintb> riscvNameToGhidraId;
/**
 * @brief Each Ghidra UserPcode type gets a set of traits assigned based on the underlying RISC-V instruction.
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
    ///@brief useful only in a vset context
    virtual int getElementSize() {return 0;};
    ///@brief useful  only in a vset context
    virtual int getMultiplier() {return 0;};
    ///@brief useful  only in a vset context
    virtual bool getTailUnchanged() {return false;};
    ///@brief useful  only in a vset context
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
 * @brief Descriptor for a single RISC-V vector instruction
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
     * @param op
     * @return a RiscvUserPcode* describing the UserPcodeOp
     */
    static const RiscvUserPcode* getUserPcode(const ghidra::PcodeOp& op);
    /**
     * @brief destroy static components
     */
    static void staticCleanup();
};
/// @todo is the following still used?
extern const std::vector<std::string> other_user_pcodeOps;
/// @brief map instruction name like 'vle8_v' to the UserPcodeOp descriptor
extern std::map<std::string, RiscvUserPcode*> riscvNameToPcodeMap;
/// @brief lookup a user pcode given Ghidra's sleigh index
extern std::map<int, riscv_vector::RiscvUserPcode*> riscvPcodeMap;
}
#endif /* USER_PCODE_HH_ */