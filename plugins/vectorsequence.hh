#ifndef __VECTORSEQUENCE_HH__
#define __VECTORSEQUENCE_HH__

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh"

namespace ghidra {

/**
 * @brief Classify the first operation of a vector sequence according
 * to its vector length specifier.
 * @details If the length is known at compile time and small
 * we will have a vsetivli instruction.  Otherwise we get a vsetvli
 * instruction
 */
typedef enum firstOp {
    OTHER,           ///<@ not a vset instruction
    VSET_IMMEDIATE,    ///<@ vector size is passed as an immediate value
    VSET_REGISTER,     ///<@ vector size is passed via register
} FirstOp ;

/**
 * @brief Collect common features from a sequence of vector instructions
 * @details This object has some similarities with the ArraySequence class
 * defined in core Ghidra.
 */
class VectorSequence
{
public:
    Funcdata* data;                   ///<@brief function data for this function
    PcodeOp* rootOp;                  ///<@brief the first node of this vector stanza
    FirstOp firstOperation;           ///<@brief is the vset instruction immediate or register
    const Address* firstOpAddr;       ///<@brief Address of the first vset instruction
    long firstOpOffset;               ///<@brief 64 bit address of the first vset instruction
    int element_width;                ///<@brief element width in bits
    Varnode* size_varnode;            ///<@brief vector length in elements, not bytes
    Varnode* current_stride_varnode;  ///<@brief number of elements handled per vector op
    Varnode* source_varnode;          ///<@brief varnode providing source addr of bytes to copy
    Varnode* dest_varnode;            ///<@brief varnode providing destination addr of bytes to copy
    std::vector<PcodeOp*> vector_loads; ///<@@brief pcodeops implementing a vector load
    std::vector<PcodeOp*> vector_stores;///<@@brief pcodeops implementing a vector store
    std::vector<PcodeOp*> other_ops;  ///<@@brief pcodeops adjacent to this vector stanza
    int search_max;                   ///<@brief number of pcodeops to consider when evaluating a transform
    bool hasLoop;                     ///<@brief true if this sequence of ops includes a self-contained backwards branch
    std::vector<Varnode*> absorbed_varnodes; ///<@brief varnodes to be absorbed in a successful transform
    bool transform();                 ///<@ execute the transformation
    VectorSequence() : data(nullptr),
                       rootOp(nullptr),
                       firstOperation(OTHER),
                       firstOpAddr(nullptr),
                       firstOpOffset(0),
                       element_width(8),
                       size_varnode(nullptr),
                       current_stride_varnode(nullptr),
                       source_varnode(nullptr),
                       dest_varnode(nullptr),
                       vector_loads(),
                       vector_stores(),
                       other_ops(),
                       search_max(5),
                       hasLoop(false) {};
};
}
#endif /* __VECTORSEQUENCE_HH__  */