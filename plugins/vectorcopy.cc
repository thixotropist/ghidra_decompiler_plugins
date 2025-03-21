
#include <iostream>
#include <fstream>
#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

#include "vectorsequence.hh"
#include "vectorcopy.hh"

namespace ghidra {

static const bool DO_TRACING = false;
extern std::ofstream logFile;

/**
 * @brief Introduce an experimental rule to transform vector
 * sequences into builtin_memcpy calls
 */

void displayPcodeOp(PcodeOp* p, const string& label)
{
    logFile << label << " PcodeOp" << std::endl << "\tRaw: " ;
    p->printRaw(logFile);
    logFile << ";\tAddr: 0x" << std::hex << p->getAddr().getOffset() << std::dec;
    logFile << ";\tNumIn: " << p->numInput() << std::endl;
}

void displayVarnode(Varnode* v, const string& label)
{
    logFile << label << " Varnode:" << "\tRaw: ";
    v->printRaw(logFile);
    logFile << ";\tflags = 0x" << std::hex << v->getFlags();
    logFile << ";\ttype = " << v->getType()->getName();
    logFile << ";\tspace = " << v->getSpace()->getName();
    logFile << ";\toffset = 0x" << v->getOffset() << std::dec << std::endl;
    logFile << "\tDescendents:" << std::endl;
    for (std::list<PcodeOp*>::const_iterator it=v->beginDescend();it!=v->endDescend();++it)
    {
        logFile <<"\t\t";
        (*it)->printRaw(logFile);
        logFile << std::endl;
    }
}

PcodeOp* insertBuiltin(VectorSequence& context, Varnode* destVn, Varnode* srcVn, Varnode* sizeVn)
{
    Funcdata* data = context.data;
    PcodeOp *copyOp = data->newOp(4,*context.firstOpAddr);
    data->opSetOpcode(copyOp, CPUI_CALLOTHER);
    data->opSetInput(copyOp, data->newConstant(4, UserPcodeOp::BUILTIN_MEMCPY), 0);
    data->opSetInput(copyOp, destVn, 1);
    data->opSetInput(copyOp, srcVn, 2);
    data->opSetInput(copyOp, sizeVn, 3);
    data->opInsertBefore(copyOp, context.rootOp); 
    return copyOp;
}

static void handleVectorLoad(PcodeOp* op, VectorSequence& context)
{
    context.vector_loads.push_back(op);
}

static void handleVectorStore(PcodeOp* op, VectorSequence& context)
{
    context.vector_stores.push_back(op);
}

static void handleAddition(PcodeOp* op, VectorSequence& context)
{
    context.other_ops.push_back(op);
}

static void handleSubtraction(PcodeOp* op, VectorSequence& context)
{
    context.other_ops.push_back(op);
}

static void handleNotEqual(PcodeOp* op, VectorSequence& context)
{
    context.other_ops.push_back(op);
}

static void handleConditionalBranch(PcodeOp *op, VectorSequence &context)
{
    displayPcodeOp(op, "Conditional Branch");
    displayVarnode(op->getIn(0), "Branch Destination");
    displayVarnode(op->getIn(1), "TBD");
    uint64_t branch_target = op->getIn(0)->getOffset();
    context.hasLoop = (branch_target < op->getAddr().getOffset()) &&
                      (branch_target >= context.firstOpOffset);
    context.other_ops.push_back(op);
    return;
}

void displayVectorSequence(VectorSequence& context)
{
    logFile << "VectorSequence:" << std::endl;
    logFile << "\tFirst Operation: " << context.firstOperation << std::endl;
    if (context.hasLoop)
    {
        logFile << "\thasLoop: True" << std::endl;
    }
    else{
        logFile << "\thasLoop: False" << std::endl;
    }
    displayVarnode(context.size_varnode, "Vector size");
    logFile << "\tNumber of vector loads: " << context.vector_loads.size() << std::endl;
    for (auto iter: context.vector_loads) 
    {
        displayPcodeOp(iter, "Vector Load");
        displayVarnode(iter->getIn(1), "Source Addr");
        displayVarnode(iter->getOut(), "Destination Register");
    }
    logFile << "\tNumber of vector stores: " << context.vector_stores.size() << std::endl;
    for (auto iter: context.vector_stores) 
    {
        displayPcodeOp(iter, "Vector Store");
        displayVarnode(iter->getIn(1), "Source Register");
        displayVarnode(iter->getIn(2), "Destination Addr");
    }
    logFile << "Other pcode operations:" << std::endl;
    for (auto iter: context.other_ops)
    {
        displayPcodeOp(iter, "Other Op");
        for (int i=0; i < iter->numInput(); i++)
        {
            displayVarnode(iter->getIn(i), "Input");
        }
        Varnode* out = iter->getOut();
        if (out != nullptr)
            displayVarnode(iter->getOut(), "Output");
    }
}

/**
 * @brief Execute any transforms matching the VectorSequence provided
 * 
 * @param context Information extracted from a sequence of vector operations
 * @return int 1 if transforms executed, 0 otherwise
 */
int transform(VectorSequence& context)
{
    const bool SIMPLE_DEBUG = false;
    const bool LOOPED_DEBUG = true;

    // Transform a simple vector load/store pair into a builtin_memcpy
    if ((context.firstOperation == VSET_IMMEDIATE) &&
        (!context.hasLoop) && 
        (context.vector_loads.size() == 1) &&
        (context.vector_stores.size() == 1) &&
        (context.vector_loads[0]->getOut() == context.vector_stores[0]->getIn(1)))
        {
            if (SIMPLE_DEBUG || DO_TRACING)
                displayVectorSequence(context);
            context.dest_varnode = context.vector_stores[0]->getIn(2);
            context.source_varnode = context.vector_loads[0]->getIn(1);
            if (SIMPLE_DEBUG || DO_TRACING)
                logFile << "Constructing a new builtin_memcpy" << std::endl;
            // This is the simplest vector copy operation
            PcodeOp* oldRoot = context.rootOp;
            context.rootOp = insertBuiltin(context, context.dest_varnode, 
                           context.source_varnode, context.size_varnode);
            if (SIMPLE_DEBUG || DO_TRACING)
                logFile << "unlinking component pcodes" << std::endl;
            context.data->opUnlink(oldRoot);
            context.data->opUnlink(context.vector_loads[0]);
            context.data->opUnlink(context.vector_stores[0]);
            if (SIMPLE_DEBUG || DO_TRACING)
                logFile.flush();
            return 1;
        }
    // Transform a simple loop of vector load/store ops into a builtin_memcpy
    if ((context.firstOperation == VSET_REGISTER) &&
        (context.hasLoop) && 
        (context.vector_loads.size() == 1) &&
        (context.vector_stores.size() == 1) &&
        (context.vector_loads[0]->getOut() == context.vector_stores[0]->getIn(1)))
        {
            if (LOOPED_DEBUG || DO_TRACING)
            {
                logFile << "Funcdata.printRaw:" << std::endl;
                context.data->printRaw(logFile);
                logFile << std::endl;
                displayVectorSequence(context);
            }
            context.dest_varnode = context.vector_stores[0]->getIn(2);
            context.source_varnode = context.vector_loads[0]->getIn(1);
            if (LOOPED_DEBUG || DO_TRACING)
                logFile << "Constructing a new builtin_memcpy" << std::endl;
            PcodeOp* oldRoot = context.rootOp;
            logFile.flush();
            //TODO: this is a stub
            return 0;
            /*
            context.rootOp = insertBuiltin(context, context.dest_varnode, 
                context.source_varnode, context.size_varnode);
            context.data->opUnlink(oldRoot);
            context.data->opUnlink(context.vector_loads[0]);
            context.data->opUnlink(context.vector_stores[0]);
            return 1;
            */
        }
        if (DO_TRACING)
            logFile << "Failed to recognize a transform:" << std::endl;
    displayVectorSequence(context);
    return 0;
}

extern std::map<std::string, UserPcodeOp*>userOpMap;

FirstOp RuleVectorCopy::getFirstOp(uintb userop_index)
{
    if ((userop_index == op_vsetvli_e8m8tama) ||
        (userop_index == op_vsetvli_e8m1tama))
        {
            return VSET_REGISTER;
        }
    if ((userop_index == op_vsetivli_e8m8tama) ||
    (userop_index == op_vsetivli_e8m1tama) ||
    (userop_index == op_vsetivli_e8mf2tama) ||
    (userop_index == op_vsetivli_e8mf4tama) ||
    (userop_index == op_vsetivli_e8mf8tama))
    {
        return VSET_IMMEDIATE;
    }
    return OTHER;
}

RuleVectorCopy::RuleVectorCopy(const string &g) : 
    Rule(g, 0, "vectorcopy"),
    // userops that can begin a memcpy block
    op_vsetvli_e8m8tama(userOpMap["vsetvli_e8m8tama"]->getIndex()),
    op_vsetivli_e8m8tama(userOpMap["vsetivli_e8m8tama"]->getIndex()),
    op_vsetvli_e8m1tama(userOpMap["vsetvli_e8m1tama"]->getIndex()),
    op_vsetivli_e8m1tama(userOpMap["vsetivli_e8m1tama"]->getIndex()),
    op_vsetivli_e8mf2tama(userOpMap["vsetivli_e8mf2tama"]->getIndex()),
    op_vsetivli_e8mf4tama(userOpMap["vsetivli_e8mf4tama"]->getIndex()),
    op_vsetivli_e8mf8tama(userOpMap["vsetivli_e8mf8tama"]->getIndex()),

    // userops that can occur within a memcpy block
    op_vle8_v(userOpMap["vle8_v"]->getIndex()),
    op_vse8_v(userOpMap["vse8_v"]->getIndex())
    {}

Rule* RuleVectorCopy::clone(const ActionGroupList &grouplist) const
{
    if (!grouplist.contains(getGroup())) {
        logFile << "RuleVectorCopy::clone failed for lack of a group" << std::endl;
        return (Rule *)0;
    }
    return new RuleVectorCopy(getGroup());
}

/**
 * @brief ask for callbacks on any CALLOTHER ops
 * @details this will include all user pcode op invocations
 * 
 * @param oplist 
 */
void RuleVectorCopy::getOpList(vector<uint4> &oplist) const {
    oplist.push_back(CPUI_CALLOTHER);
}

/**
 * @brief does the current block match a vector copy rule?
 * 
 * @param op 
 * @param data 
 * @return int4 
 */
int4 RuleVectorCopy::applyOp(PcodeOp *op, Funcdata &data) {

    const bool DEBUG = false;
    VectorSequence context;

    if (false && DEBUG)
    {
        logFile << "RuleVectorCopy::applyOp called:" << std::endl;
        logFile << "\tFunction start addr: " << std::hex << data.getAddress() << std::dec << std::endl;
        op->printRaw(logFile);
        logFile << std::endl;
        logFile << "pcodeop = \n";
    }
    // The first input arg to CALLOTHER identifies the pcodeop
    const Varnode* varnode_userop = op->getIn(0);
    // This varnode points to a pcode function

    // user pcodeop index can be retrieved from the varnode 
    uintb userop_index = varnode_userop->getOffset();
    // require one of several vset* instructions to begin this pattern,
    // adjusting the maximum number of pcode ops to examine
    context.firstOperation = getFirstOp(userop_index);
    switch(context.firstOperation) {
        case OTHER: return 0;
        case VSET_IMMEDIATE:
            context.search_max = 5;
            break;
        case VSET_REGISTER:
            context.search_max = 10;
            break;
        default:
        std::cerr << "Unrecognized first Operation classification!" << std::endl;
            return 0;
    }
    if (context.firstOperation == OTHER)
        return 0;
    // we have a vsetivli or vsetvli instruction
    context.data = &data;
    context.rootOp = op;
    context.firstOpAddr = &op->getAddr();
    context.firstOpOffset = op->getAddr().getOffset();
    if (DEBUG)
    {
        displayPcodeOp(op, "Initial Op");
        displayVarnode(op->getIn(0), "Initial Op In(0)");
        displayVarnode(op->getIn(1), "Initial Op In(1)");
        if (op->getOut() != nullptr)
        {
            displayVarnode(op->getOut(), "Initial Op Out");
        }
    }
    if (DEBUG)
        logFile << "Found a valid first userop of the stanza" << std::endl;
    // There is an optional output variable, the number of elements processed
    // by vector ops - aka the stride
    context.current_stride_varnode =  op->getOut();
    // the vset* instruction sets the number of elements and the current stride
    // The size, or total number of elements to process, can be either a register or a constant
    context.size_varnode = op->getIn(1);
    if (context.size_varnode == nullptr) return 0;
    if (DEBUG && (context.current_stride_varnode != nullptr))
    {
        displayVarnode(context.current_stride_varnode, "Stride");
    }
    // make sure we have memcpy registered as a builtin
    data.getArch()->userops.registerBuiltin(UserPcodeOp::BUILTIN_MEMCPY);
    int opCounter = 1;
    context.source_varnode = nullptr;
    for (PcodeOp* next = op->nextOp(); next != nullptr; next = next->nextOp())
    {
        if (DEBUG) {
            logFile << "Pcode (code, opcode_name):\t" << next->code() << "," << next->getOpName() << std::endl;
            next->printRaw(logFile);
            logFile << std::endl;
        }
        if (next->code() == CPUI_CALLOTHER)
        {
            if (DEBUG)
                logFile << "\tCallOther: 0x" << std::hex << next->getIn(0)->getOffset() << std::dec << std::endl;
            if (next->getIn(0)->getOffset() == op_vle8_v)
            {
                handleVectorLoad(next, context);
                continue;
            }
            if (next->getIn(0)->getOffset() == op_vse8_v)
            {
                handleVectorStore(next, context);
                continue;
            }
        }
        if (next->code() == CPUI_CBRANCH)
        {
            handleConditionalBranch(next, context);
        }
        // looking for addition, subtraction, and comparison ops
        if (DEBUG)
            logFile << "Found pcodeop: " << next->getOpName() << std::endl;
        const std::string& opName = next->getOpName();
        if (opName == "+")
        {
            handleAddition(next, context);
            continue;
        }
        if (opName == "-")
        {
            handleSubtraction(next, context);
            continue;
        }
        if (opName == "!=")
        {
            handleNotEqual(next, context);
            continue;
        }
        if ((opCounter++ >= context.search_max) ||
            (next->code() == CPUI_RETURN) ||
            (next->code() == CPUI_CALL) ||
            (next->code() == CPUI_CALLIND) ||
            (next->code() == CPUI_BRANCH) ||
            (next->code() == CPUI_BRANCHIND))
        {
            break;
        }
    }
    // Evaluate the vector sequence against the set of rules,
    // executing the first transform that matches
    return transform(context);

    //PcodeOp* newRoot = insertBuiltin(context, data, context.destination_varnode, 
    //    context.source_varnode, context.size_varnode);
    //for (int slot = 0; slot < context.rootOp->numInput(); slot++)
    //{
    //    data.opRemoveInput(context.rootOp, slot);
    //}
    //data.opDestroy(context.rootOp);
    //context.rootOp = newRoot;
    if (DEBUG)
    {
        logFile << "builtin_memcpy pattern recognized and new pcodeop inserted" << std::endl;
    }
    return 0;
    //HeapSequence sequence(data,ct,op);
    //if (!sequence.isValid())
    //    return 0;
    //if (!sequence.transform())
    //    return 0;
    return 0;
}
}    