/**
 * @file vector_ops.cc
 * @author thixotropist
 * @brief Model RISC-V vector operands
 * @date 2025-10-07
 *
 * @copyright Copyright (c) 2025
 */
#include <stack>
#include "framework.hh"
#include "vector_ops.hh"
#include "riscv.hh"
#include "riscv_sleigh.hh"

namespace riscv_vector{

VectorOperand::~VectorOperand() {}

static std::vector<std::string> opTypeToString;

void VectorOperand::static_init()
{
    opTypeToString = { "load", "store", "read-modify-write", "constant", "indexer", "other"};
}
void VectorOperand::printRaw(std::stringstream& ss)
{
    ss << "\tOperand Type: " << opTypeToString[opType] << std::endl;
    if (vRegister != nullptr)
    {
        ss << "\tVRegister: ";
        vRegister->printRaw(ss);
        ss << std::endl;
    }
    if (pRegister != nullptr)
    {
        ss << "\tpRegister: ";
        pRegister->printRaw(ss);
        ss << std::endl;
    }
     if (pExternal != nullptr)
     {
        ss << "\tpExternal: ";
        pExternal->printRaw(ss);
        ss << std::endl;
     }
    std::string vector_register_name;
    ghidra::getRegisterName(vector_register, &vector_register_name);
    ss << "\tVector Register: " << vector_register_name << std::endl;
    std::string pointer_register_name;
    ghidra::getRegisterName(pointer_register, &pointer_register_name);
    ss << "\tpointer Register: " << pointer_register_name << std::endl;
}

static std::vector<std::string> operationTypeToString;

void VectorOperation::static_init()
{
    VectorOperand::static_init();
    operationTypeToString = {
        "unknown",
        "copy",
        "load",
        "addition",
        "pointer_addition",
        "subtraction",
        "multiplication",
        "twos complement",
        "comparison",
        "conditional branch",
        "vector setup",
        "load vector from memory",
        "load vector from memory, fail only first",
        "store vector to memory",
        "vector to vector operation",
        "vector and immediate scalar to vector",
        "vector and vector to vector",
        "vector to scalar",
        "vector comparison"
    };
}

VectorOperation::VectorOperation(OperationType typeParam, ghidra::PcodeOp* opParam) :
    type(typeParam),
    op(opParam),
    arg0(nullptr),
    arg1(nullptr),
    arg2(nullptr)
{
    // result may be null
    result = op->getOut();
    // the first argument is always CALL_OTHER, so we skip it
    // note the fallthrough nature of this switch statement
    switch(op->numInput()){
        case 4:
            arg2 = op->getIn(3);
        case 3:
            arg1 = op->getIn(2);
        case 2:
            arg0 = op->getIn(1);
            break;
        default:
            ghidra::pLogger->warn("Unrecognized number of vector pcode arguments");
    }
}

ScalarOperation::ScalarOperation(OperationType typeParam, ghidra::PcodeOp* opParam) :
    type(typeParam),
    op(opParam),
    arg0(nullptr),
    arg1(nullptr),
    arg2(nullptr)
{
    // result may be null
    result = op->getOut();

    switch(op->numInput()){
        case 3:
            arg2 = op->getIn(2);
        case 2:
            arg1 = op->getIn(1);
        case 1:
            arg0 = op->getIn(0);
            break;
        default:
            ghidra::pLogger->warn("Unrecognized number of scalar pcode arguments");
    }
}

static std::set<ghidra::intb> seriesAnalyzed; // only report on a series on the first visit.
VectorSeries::VectorSeries(ghidra::PcodeOp *firstOp, ghidra::Funcdata &data_param, const RiscvUserPcode* vsetInfo) :
    data(data_param)
{
    if (transformCountNonLoop >= TRANSFORM_LIMIT_NONLOOPS)
        return;
    // firstOp is a vsetivli instruction
    numBytes = firstOp->getIn(1)->getOffset() * vsetInfo->multiplier * vsetInfo->elementSize;

    // collect viable vector load instructions
    currentBlock = firstOp->getParent();
    ghidra::PcodeOp* nextOp = firstOp->nextOp();
    while ((nextOp != nullptr) && (nextOp->getParent() == currentBlock))
    {
        ghidra::PcodeOp* op = nextOp;
        nextOp = op->nextOp();
        const RiscvUserPcode *opInfo = RiscvUserPcode::getUserPcode(*op);
        // ignore ops that have no vector component
        if ((opInfo == nullptr))
        {
            continue;
        }
        // stop scanning if we find another vset instruction
        if (opInfo->isVset || opInfo->isVseti)
        {
            break;
        }
        if (opInfo->isLoad || opInfo->isLoadImmediate)
        {
            ghidra::pLogger->trace("Found a load or load immediate instruction at 0x{0:x}",
                op->getAddr().getOffset());
            loadSet.push_back(op);
        }
    }
    ghidra::intb firstAddr = firstOp->getAddr().getOffset();
    auto exists = seriesAnalyzed.find(firstAddr);
    if (exists == seriesAnalyzed.end())
    {
        seriesAnalyzed.insert(firstAddr);
        reportFile << "Vector Series:\n\tSequence start address: 0x" << std::hex <<
            firstAddr << std::endl << std::dec <<
            "\tvset op: " << vsetInfo->asmOpcode << std::endl <<
            "\telement size: " << vsetInfo->elementSize << std::endl <<
            "\tnumber of bytes: " << numBytes << std::endl <<
            "\tvector loads: " << loadSet.size() << std::endl;
    }
}
int VectorSeries::match()
{
    std::vector<std::pair<ghidra::PcodeOp *, ghidra::PcodeOp *> *> pcodesToBeBuilt;
    std::vector<ghidra::PcodeOp *> deleteSet; ///< collect PcodeOps to delete if we get at least one successful transform
    bool trace = ghidra::pLogger->should_log(spdlog::level::trace);
    ghidra::FunctionEditor functionEditor(data);
    int numTransformedStores = 0;
    // for each vector load instruction, locate matching vector store instructions
    // within the same block
    for (auto loadOp: loadSet)
    {
        ghidra::Varnode* sourceVn = loadOp->getIn(1);
        const RiscvUserPcode *opInfo = RiscvUserPcode::getUserPcode(*loadOp);
        bool isMemset = sourceVn->isConstant() && opInfo->isLoadImmediate;
        ghidra::intb builtinOp;
        if (isMemset)
            builtinOp = VECTOR_MEMSET;
        else
            builtinOp = VECTOR_MEMCPY;
        // iterate over the descendents reading the output vector register
        int numOtherDependencies = 0;
        ghidra::Varnode *outputVn = loadOp->getOut();
        if (outputVn == nullptr)
        {
            ghidra::pLogger->warn("Ghidra has lost the dependencies of the vector load op at 0x{0:x}",
                loadOp->getAddr().getOffset());
            continue;
        }
        ghidra::pLogger->info("Exploring dependencies of the vector load op at 0x{0:x}",
            loadOp->getAddr().getOffset());
        for (auto it = outputVn->beginDescend(); it != outputVn->endDescend(); ++it)
        {
            ghidra::PcodeOp* descOp = *it;
            if (currentBlock != descOp->getParent()) continue;
            const RiscvUserPcode *descOpInfo = RiscvUserPcode::getUserPcode(*descOp);
            // we only transform vector store opcodes
            if ((descOpInfo == nullptr) || (!descOpInfo->isStore)) {
                // we can't delete this vector load op
                reportFile << "\tLoad op at 0x" << std::hex << loadOp->getAddr().getOffset() <<
                    " has a non-store dependency at 0x" << descOp->getAddr().getOffset() <<
                    " and can not be absorbed" << std::dec << std::endl;
                numOtherDependencies++;
                break;
            }
            numTransformedStores++;
            ghidra::pLogger->info("Inserting vector op 0x{0:x} at 0x{1:x}",
                            builtinOp, (*it)->getAddr().getOffset());
            reportFile << "\tLoad op at 0x" << std::hex << loadOp->getAddr().getOffset() <<
                " has a valid dependent vector store op at 0x" <<
                descOp->getAddr().getOffset() << std::dec << std::endl;
            // vector_mem* invocations count bytes, not elements.
            // construct a new constant Varnode to hold the number of bytes
            ghidra::Varnode *new_size_varnode = data.newConstant(1, numBytes);
            ghidra::Varnode *destVn = (*it)->getIn(2);
            // we have destination, source, and size so construct the vector_mem* op
            ghidra::PcodeOp *newOp = insertVoidCallOther(data, (*it)->getAddr(), builtinOp, destVn, sourceVn, new_size_varnode);
            if (trace) ghidra::inspector->log("  queued for insertion vector opcode", newOp);
            // accumulate pcode additions and deletions as a pending transaction
            pcodesToBeBuilt.push_back(new std::pair<ghidra::PcodeOp *, ghidra::PcodeOp *>(newOp, *it));
            deleteSet.push_back(*it);
            ++transformCountNonLoop;
        }
        // Can we delete the vector load operation too?
        if (numOtherDependencies == 0) deleteSet.push_back(loadOp);
        for (auto it : pcodesToBeBuilt)
        {
            // queue pending vector_mem* insertions
            data.opInsertBefore(it->first, it->second);
            std::stringstream ss;
            it->first->printRaw(ss);
            ghidra::pLogger->trace("  Inserted vector opcode: {0:s}",
                ss.str());
            delete it;
        }
        pcodesToBeBuilt.clear();
    }
    for (auto iter : deleteSet)
    {
        ghidra::Varnode *outVn = iter->getOut();
        if (outVn == nullptr)
            functionEditor.deleteOp(iter, "VectorSeries::match");
        else
        {
            std::list<ghidra::PcodeOp *>::const_iterator endIter = outVn->endDescend();
            std::list<ghidra::PcodeOp *>::const_iterator startIter = outVn->beginDescend();
            if (startIter == endIter)
               functionEditor.deleteOp(iter, "singleton descendent");
        }
    }
    if (numTransformedStores == 0)
    {
        ghidra::pLogger->flush();
        return ghidra::RETURN_NO_TRANSFORM;
    }
    if (ghidra::inspector->audit_block_graph)
        {
            std::ofstream outFile("/tmp/memcpy_blockgraph_audit.log");
            ghidra::inspector->auditBlockGraph(data, outFile);
            outFile.close();
        }
    ghidra::pLogger->flush();
    return ghidra::RETURN_TRANSFORM_PERFORMED;
}

static std::map<int, VectorLoop::userPcodeOpHandler> opHandlers;
static std::vector<std::string> fTypeToString;
void VectorLoop::static_init()
{
    VectorOperation::static_init();
        ghidra::pLogger->trace("Adding VectorLoop instruction handlers to opHandlers map");

    // instructions found in many vector stanzas, starting with vector_memcpy
    opHandlers[riscvNameToGhidraId["vsetvli_e8m1tama"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorSetup, op);
            loop.vectorOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vle8_v"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoad, op);
            loop.vectorOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vse8_v"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorStore, op);
            loop.vectorOps.push_back(vOp);
        };
    // instructions found in vector_strlen stanzas
    opHandlers[riscvNameToGhidraId["vle8ff_v"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            loop.loopFlags |= RISCV_VEC_INSN_FAULT_ONLY_FIRST;
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoadFF, op);
            loop.vectorOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vmseq_vi"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            // First operand is a vector register, second operand is an integer immediate.
            // Result is a vector register
            VectorOperation* vOp = new VectorOperation(OperationType::vectorComparison, op);
            loop.vectorOps.push_back(vOp);
            loop.vComparisonOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vfirst_m"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorComparison, op);
            loop.vectorOps.push_back(vOp);
            loop.vLogicalOps.push_back(vOp);
        };
    // instructions found in vector_strcmp stanzas
    opHandlers[riscvNameToGhidraId["vmsne_vv"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
                VectorOperation* vOp = new VectorOperation(OperationType::vectorComparison,  op);
                loop.vectorOps.push_back(vOp);
                loop.vComparisonOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vmseq_vi"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
                VectorOperation* vOp = new VectorOperation(OperationType::vectorComparison, op);
                loop.vectorOps.push_back(vOp);
                loop.vComparisonOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vmor_mm"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
                VectorOperation* vOp = new VectorOperation(OperationType::vectorPairToVector, op);
                loop.vectorOps.push_back(vOp);
                loop.vLogicalOps.push_back(vOp);
        };
    fTypeToString = {"memcpy", "memset", "strlen",  "transform",  "reduce",
        "innerProduct", "unknown", "other"};
}
VectorLoop::VectorLoop(ghidra::Funcdata& dataParam, bool traceParam) :
    terminationConditionFlags(0),
    typ(unknown),
    name("pending"),
    loopFlags(0x0),
    loopFound(false),
    data(dataParam),
    functionEditor(data),
    vsetOp(nullptr),
    codeSpace(nullptr),
    loopBlock(nullptr),
    terminationVarnode(nullptr),
    comparisonVarnode(nullptr),
    terminationControl(nullptr),
    terminationBranchOp(nullptr),
    comparisonOp(ghidra::CPUI_MAX),
    simpleFlowStructure(false),
    numElements(nullptr),
    multiplier(0),
    elementSize(0),
    vlReg(0),
    vlAddrReg(0),
    vlAddrIncrReg(0),
    vsReg(0),
    vsAddrReg(0),
    vsAddrIncrReg(0),
    elementCounterReg(0),
    trace(traceParam)
{
}

void VectorLoop::analyze(ghidra::PcodeOp* vsetOp)
{
    examine_control_flow(vsetOp);
    // warn if this vset op doesn't start a loop
    if (!loopFound)
    {
        ghidra::pLogger->warn("Unable to fully analyze potential complex vector loop stanza at 0x{0:x}",
            firstAddr);
    }
    ghidra::pLogger->info("Analyzing potential vector loop stanza at 0x{0:x} in pid:tid {1:d}:{2:d}",
        firstAddr, getpid(), gettid());
    // Phi (or Multiequal nodes) provide the locations at which
    // registers and memory locations are set. They are found at the top of a block
    // and are essential in determining heritages and dependencies
    collect_phi_nodes();
    // Identify key registers and vector operations within a loop,
    // checking for unexpected elements that may veto a match.
    // Begin modeling this as a potential vector function.
    examine_loop_pcodeops(loopBlock);
    // Identify common loop elements like vector loads, vector stores, and element counters
    collect_common_elements();
    // Identify vector and other instructions found immediately after the loop,
    // perhaps indicative of a reduction operation
    examine_loop_epilog();
    // Summarize key features to a report file
    generateReport();
}

bool VectorLoop::invokeVectorOpHandler(ghidra::PcodeOp* op)
{
    const RiscvUserPcode* opInfo = RiscvUserPcode::getUserPcode(*op);
    auto f = opHandlers.find(opInfo->ghidraOp);
    if (f != opHandlers.end())
    {
        std::function<void(VectorLoop& loop, int ghidraOp, ghidra::PcodeOp* op)> handler = f->second;
        (handler)(*this, opInfo->ghidraOp, op);
        return true;
    }
    else
    {
        ghidra::pLogger->info("Found no instruction handler, sending to unhandledVectorOps:");
        unhandledVectorOps.push_back(new VectorOperation(OperationType::unknown, op));
    }
    return false;
}

bool VectorLoop::isDefinedInLoop(const ghidra::Varnode* vn)
{
    ghidra::inspector->log("\tChecking for in-loop definition", vn);
    if ((vn->getAddr().getSpace() == ghidra::csRegisterAddrSpace))
    {
        ghidra::uintb offset = vn->getAddr().getOffset();
        ghidra::pLogger->trace("\tCSR offset is 0x{0:x}", offset);
        ghidra::inspector->log("\tExamining Varnode", vn);
        // TODO: figure out how to look this index up
        if (offset == 0x6100)
        {
            ghidra::inspector->log("\tVarnode references vector register vl and is likely modified in loop", vn);
            return true;
        }
        else
        {
            std::stringstream ss;
            vn->getAddr().printRaw(ss);
            ghidra::pLogger->warn("\tVarnode {0:s} references unknown control and status register , definition in loop unknown",
                ss.str());
            return false;
        }
    }
    const ghidra::PcodeOp* definingOp = vn->getDef();
    if (definingOp == nullptr)
    {
        ghidra::inspector->log("\tVarnode has no defining Opcode", vn);
        return false;
    }
    ghidra::intb offset = definingOp->getAddr().getOffset();
    bool addressInLoop = (offset >= firstAddr) && (offset <= lastAddr);
    bool blockIsLoopblock = definingOp->getParent() == loopBlock;
    ghidra::pLogger->trace("\t\taddressInLoop = {0:s}", addressInLoop ? true : false);
    ghidra::pLogger->trace("\t\tblockIsLoopblock = {0:s}", blockIsLoopblock ? true : false);
    return addressInLoop && blockIsLoopblock;
}

void VectorLoop::log()
{
    ghidra::pLogger->info("VectorLoop info:\n"
        "\tname = {0:s}\n"
        "\ttype = {1:s}\n"
        "\tLoop Flags = 0x{2:x}\n"
        "\tNumber of vector operations = {3:d}\n"
        "\tNumber of scalar operations = {4:d}",
        name, fTypeToString[static_cast<int>(typ)], loopFlags,
        vectorOps.size(), scalarOps.size());
    for (auto operation: vectorOps)
    {
        ghidra::pLogger->info("\tVector Operation type {0:s}",
            operationTypeToString[static_cast<int>(operation->type)]);
    }
    for (auto operation: scalarOps)
    {
        ghidra::pLogger->info("\tScalar Operation type {0:s}",
            operationTypeToString[static_cast<int>(operation->type)]);
    }
}

void VectorLoop::examine_control_flow(ghidra::PcodeOp* vsetOpParam)
{
    vsetOp = vsetOpParam;
    loopBlock = vsetOp->getParent();
    firstAddr = loopBlock->firstOp()->getAddr().getOffset();
    lastAddr = loopBlock->getStop().getOffset();
    codeSpace = vsetOp->getAddr().getSpace();
     // Locate any blocks that flow into the loop
    collect_related_blocks();
    // Get the Ghidra block containing this loop
    ghidra::PcodeOp* lastOp = loopBlock->lastOp();
    bool isBranch = lastOp->isBranch();
    // this block forms a loop if it starts with a vset and ends
    // with a conditional branch back to the start
    // TODO: some vector loops (like strncmp) include an additional
    // branch instruction.  The current code fails to match on such loops.
    if (isBranch && (lastOp->code() == ghidra::CPUI_CBRANCH))
    {
        ghidra::intb branchTarget = lastOp->getIn(0)->getAddr().getOffset();
        terminationVarnode = lastOp->getIn(1);
        if (branchTarget == firstAddr)
        {
            simpleFlowStructure = true;
            loopFound = true;
        }
        else
        {
            simpleFlowStructure = false;
            loopFound = false;
            //TODO: test the next block to see if it ends in a return to this block
        }
    }
}

void VectorLoop::collect_phi_nodes()
{
    ghidra::Address loopStart = vsetOp->getParent()->getStart();
    ghidra::PcodeOpTree::const_iterator iter = data.beginOp(loopStart);
    ghidra::PcodeOpTree::const_iterator enditer = data.endOp(loopStart);
    // This loop collects PcodeOps that begin a loop holding a vsetop
    ghidra::pLogger->trace("  Iterating over vset phi pcodes");
    std::stringstream ss;
    while(iter!=enditer) {
        // iter points at a (SeqNum, PcodeOp*) pair
        ghidra::PcodeOp *op = (*iter).second;
         ++iter;
         if (op->code() == ghidra::CPUI_MULTIEQUAL)
         {
            // ignore all RAM and stack phi nodes
            if (op->getOut() == nullptr)
                continue;
            const ghidra::AddrSpace* spaceId = op->getOut()->getAddr().getSpace();
            if ((spaceId == ghidra::ramAddrSpace) || (spaceId == ghidra::stackAddrSpace)) continue;
            if (trace)
            {
                op->printRaw(ss);
                ghidra::pLogger->trace("  Analysis of Phi node: {0:s}", ss.str());
                ss.str("");
            }
            for (int slot = 0; slot < op->numInput(); ++slot)
            {
                const ghidra::Varnode* vn = op->getIn(slot);
                // where does this arg get written?
                ghidra::inspector->log("\tAnalysis of Varnode", op->getIn(slot), slot);
                // ignore any self-references
                if (op->getIn(slot) == op->getOut())
                {
                    ghidra::inspector->log("\t\tVarnode is both input and output", op->getIn(slot), slot);
                    continue;
                }
                if (isDefinedInLoop(vn))
                {
                    ghidra::inspector->log("\tAdding to phiNodesAffectedByLoop", op);
                    phiNodesAffectedByLoop.push_back(op);
                    break;
                }
            }
        }
    }
    ghidra::pLogger->trace("  Found {0:d} Phi nodes affected by the loop", phiNodesAffectedByLoop.size());
    // Build a map from Phi node output registers to the Varnodes they may be set from, excluding loop-internal registers
    for (auto op: phiNodesAffectedByLoop)
    {
        const ghidra::Varnode* outVn = op->getOut();
        if (outVn->getAddr().getSpace() == ghidra::registerAddrSpace)
        {
            ghidra::uintb outputRegister = outVn->getAddr().getOffset();
            std::vector<ghidra::Varnode*>* heritageVns = new std::vector<ghidra::Varnode*>();
            // collect valid sources, excluding Varnodes defined within the loop or obvious duplicates
            for (int i = 0; i < op->numInput(); i++)
            {
                ghidra::Varnode* validSource = op->getIn(i);
                if (isDefinedInLoop(validSource) ||
                    (std::find(heritageVns->begin(), heritageVns->end(), validSource) != heritageVns->end())) continue;
                heritageVns->push_back(validSource);
            }
            registerPhiMapping[outputRegister] = heritageVns;
        }
        else if (outVn->getAddr().getSpace() == ghidra::csRegisterAddrSpace)
        {
            ghidra::uintb csOutputRegister = outVn->getAddr().getOffset();
            std::vector<ghidra::Varnode*>* heritageVns = new std::vector<ghidra::Varnode*>();
            // collect valid sources, excluding Varnodes defined within the loop or obvious duplicates
            for (int i = 0; i < op->numInput(); i++)
            {
                ghidra::Varnode* validSource = op->getIn(i);
                if (isDefinedInLoop(validSource) ||
                    (std::find(heritageVns->begin(), heritageVns->end(), validSource) != heritageVns->end())) continue;
                heritageVns->push_back(validSource);
            }
            csRegisterPhiMapping[csOutputRegister] = heritageVns;
        }
    }
    // log the Phi mappings
    if (trace)
    {
        for (auto const& [key, val] : registerPhiMapping)
        {
            std::string regName;
            ghidra::getRegisterName(key, &regName);
            ghidra::pLogger->trace("Phi Node for register {0:s}:", regName);
            for (auto vn: (*val) )
            {
                vn->printRaw(ss);
                ss << ", ";
            }
            ghidra::pLogger->trace("\t{0:s}:", ss.str());
            ss.str("");
        }
        for (auto const& [key, val] : csRegisterPhiMapping)
        {
            std::string regName;
            ghidra::getRegisterName(key, &regName);
            ghidra::pLogger->trace("Phi Node for control and status register {0:s}:", regName);
            for (auto vn: (*val) )
            {
                vn->printRaw(ss);
                ss << ", ";
            }
            ghidra::pLogger->trace("\t{0:s}:", ss.str());
            ss.str("");
        }
    }
}

void VectorLoop::examine_loop_pcodeops(const ghidra::BlockBasic* loopBlock)
{
    std::stringstream ss;
    trace = ghidra::pLogger->should_log(spdlog::level::trace);
    std::list<ghidra::PcodeOp*>::const_iterator it = loopBlock->beginOp();
    std::list<ghidra::PcodeOp*>::const_iterator lastOp = loopBlock->endOp();
    bool analysisFailed = false;
    ghidra::pLogger->trace("Beginning loop pcode analysis");
    while (it != lastOp && !analysisFailed)
    {
        ghidra::PcodeOp* op = *it;
        ++it;
        ghidra::intb opOffset = op->getAddr().getOffset();
        if (trace)
        {
            op->printRaw(ss);
            ghidra::pLogger->trace("  PcodeOp at 0x{0:x}: {1:s}",  opOffset, ss.str());
            ss.str("");
        }
        // collect all regular PcodeOps in the loop to make erasing them
        // easier
        if (op->code() != ghidra::CPUI_MULTIEQUAL) loopOps.push_back(op);
        switch(op->code())
        {
          case ghidra::CPUI_BRANCH:
            simpleFlowStructure = false;
            break;
          case ghidra::CPUI_CBRANCH:
            // there should only be one of these
            scalarOps.push_back(new ScalarOperation(OperationType::conditionalBranch, op));
            break;
          case ghidra::CPUI_BRANCHIND:
            // indirect branches are unexpected
            simpleFlowStructure = false;
            break;
          case ghidra::CPUI_CALL:
            // function calls are unexpected
            simpleFlowStructure = false;
            analysisFailed = true;
            break;
          case ghidra::CPUI_RETURN:
            // function returns are unexpected
            simpleFlowStructure = false;
            analysisFailed = true;
            break;
          case ghidra::CPUI_INT_EQUAL:
          case ghidra::CPUI_INT_NOTEQUAL:
          case ghidra::CPUI_INT_SLESS:
          case ghidra::CPUI_INT_SLESSEQUAL:
          case ghidra::CPUI_INT_LESS:
          case ghidra::CPUI_INT_LESSEQUAL:
            // loop condition test
            scalarOps.push_back(new ScalarOperation(OperationType::comparison, op));
            comparisonOp = op->code();
            break;
          case ghidra::CPUI_INT_ADD:
            // integer adds are common pointer ops
            scalarOps.push_back(new ScalarOperation(OperationType::addition, op));
            break;
          case ghidra::CPUI_INT_SUB:
            // integer subtracts are common counter decrements
            scalarOps.push_back(new ScalarOperation(OperationType::subtraction, op));
            break;
          case ghidra::CPUI_PTRADD:
            // integer adds are common pointer ops
            scalarOps.push_back(new ScalarOperation(OperationType::pointerAddition, op));
            break;
          case ghidra::CPUI_INT_MULT:
            // Probably a multiply by -1
            scalarOps.push_back(new ScalarOperation(OperationType::multiplication, op));
            break;
          case ghidra::CPUI_INT_2COMP:
            // Twos complement, sometimes part of a subtraction
            scalarOps.push_back(new ScalarOperation(OperationType::twosComplement, op));
            break;
          case ghidra::CPUI_CAST:
            // Ignore cast pcodes for now
            break;
          case ghidra::CPUI_MULTIEQUAL:
            // handled separately at the top of the loop
            break;
          case ghidra::CPUI_COPY:
            scalarOps.push_back(new ScalarOperation(OperationType::copy, op));
            break;
          case ghidra::CPUI_LOAD:
            scalarOps.push_back(new ScalarOperation(OperationType::load, op));
            break;
          case ghidra::CPUI_CALLOTHER:
            {
                const RiscvUserPcode* opInfo = RiscvUserPcode::getUserPcode(*op);
                if ((opInfo == nullptr) || (!opInfo->isVectorOp))
                {
                    // may be other builtin pcodes
                    otherUserPcodes.push_back(op);
                }
                else if (opInfo->isVset)
                {
                    invokeVectorOpHandler(op);
                    break;
                }
                else
                {
                    invokeVectorOpHandler(op);
                }
                break;
            }
            default:
            {
                otherScalarOps.push_back(new ScalarOperation(OperationType::unknown, op));
                int opcode = op->code();
                ghidra::pLogger->warn("    Unexpected Ghidra op found in analysis: {0:d}", opcode);
            }
        }
    }
}
void VectorLoop::collect_common_elements()
{
    for (auto vOp: vectorOps)
    {
        ghidra::PcodeOp* op = vOp->op;
        const ghidra::Varnode* opResult = op->getOut();
        const RiscvUserPcode *vsetInfo = RiscvUserPcode::getUserPcode(*op);
        std::vector<ghidra::Varnode*>* heritageVarnodes;
        switch(vOp->type)
        {
            case OperationType::vectorSetup:
                multiplier = vsetInfo->multiplier;
                elementSize = vsetInfo->elementSize;
                heritageVarnodes = registerPhiMapping[vOp->arg0->getAddr().getOffset()];
                if (heritageVarnodes != nullptr && heritageVarnodes->size() > 0)
                    numElements = (*heritageVarnodes)[0];
                if (opResult != nullptr)
                    loopLocalVns.push_back(op->getOut());
                break;
            case OperationType::vectorLoad:
            case OperationType::vectorLoadFF:
                vLoadOps.push_back(vOp);
                break;
            case OperationType::vectorStore:
                vStoreOps.push_back(vOp);
                break;
            default:
                break;
        }
    }
    for (auto op: scalarOps)
    {
        switch(op->type)
        {
            case OperationType::comparison:
            {
                sComparisonOps.push_back(op);
                // where is the comparison register set?
                ghidra::PcodeOp* testedOp = op->arg0->getDef();
                if (testedOp == nullptr) break;
                const RiscvUserPcode *vsetInfo = RiscvUserPcode::getUserPcode(*testedOp);
                // very crude determination!
                if (vsetInfo == nullptr)
                    terminationConditionFlags |= TERMINATES_ON_COUNTDOWN;
                else
                    terminationConditionFlags |= TERMINATES_ON_DATA_TEST;
                std::stringstream ss;
                testedOp->printRaw(ss);
                comparisonVarnode = testedOp->getOut();
                ghidra::pLogger->trace("Comparison target = {0:s}\n\tTermination flags = 0x{1:x}",
                    ss.str(), terminationConditionFlags);
                break;
            }
            case OperationType::conditionalBranch:
                terminationBranchOp = op->op;
                break;
            case OperationType::multiplication:
            case OperationType::addition:
            case OperationType::pointerAddition:
            case OperationType::subtraction:
                sIntegerOps.push_back(op);
                loopLocalVns.push_back(op->op->getOut());
                break;
            case OperationType::copy:
                ghidra::pLogger->trace("Found a Copy operation");
                if(op->arg0->getAddr().getSpace() == ghidra::csRegisterAddrSpace)
                {
                    ghidra::pLogger->info("Found a reference to a CSR register");
                }
                break;
            case OperationType::unknown:
                ghidra::pLogger->trace("Found an unknown scalar operation");
                break;
            default:
                ghidra::pLogger->trace("Found a scalar operation without a handler");
                break;
        }
    }

    // Collect the loop source contexts for each vector load
    for (auto vop: vLoadOps)
    {
        VectorOperand* vOperand = new VectorOperand(VectorOperand::load);
        vOperand->vRegister = vop->result;
        vOperand->vector_register = vOperand->vRegister->getOffset();
        vOperand->pRegister = vop->arg0;
        std::stringstream ss;
        if (trace)
        {
            vOperand->pRegister->printRaw(ss);
            ghidra::pLogger->trace("Searching for Phi node referencing {0:s}", ss.str());
            ss.str("");
        }
        vOperand->pointer_register = vOperand->pRegister->getOffset();
        std::vector<ghidra::Varnode*>* heritageVarnodes = registerPhiMapping[vOperand->pointer_register];
        if (heritageVarnodes != nullptr && heritageVarnodes->size() > 0)
            vOperand->pExternal = (*heritageVarnodes)[0];
        if (vOperand->pExternal == nullptr)
            ghidra::pLogger->warn("Failed to extract Vector load pExternal varnode from Phi nodes");
        loopLocalVns.push_back(vOperand->pRegister);
        vSourceOperands.push_back(vOperand);
    }
    for (auto vop: vStoreOps)
    {
        VectorOperand* vOperand = new VectorOperand(VectorOperand::store);
        vOperand->vRegister = vop->arg0;
        vOperand->pRegister = vop->arg1;
        // search for a Phi node referencing this register
        std::stringstream ss;
        if (trace)
        {
            vOperand->pRegister->printRaw(ss);
            ghidra::pLogger->trace("Searching for Phi node referencing {0:s}", ss.str());
            ss.str("");
        }
        vOperand->pointer_register = vOperand->pRegister->getOffset();
        std::vector<ghidra::Varnode*>* heritageVarnodes = registerPhiMapping[vOperand->pointer_register];
        if (heritageVarnodes != nullptr && heritageVarnodes->size() > 0)
            vOperand->pExternal = (*heritageVarnodes)[0];
        if (vOperand->pExternal == nullptr)
        {
            vOperand->pRegister->printRaw(ss);
            ghidra::pLogger->warn("Failed to extract Vector store pExternal varnode from Phi nodes\n"
            "\tpRegister: {0:s}", ss.str());
            ss.str("");
        }
        loopLocalVns.push_back(vOperand->pRegister);
        vDestinationOperands.push_back(vOperand);
    }
    // Determine how the loop terminates if this is a single-condition loop
    if (sComparisonOps.size() == 1)
    {
        terminationControl = sComparisonOps[0]->arg0->getDef();
        loopLocalVns.push_back(sComparisonOps[0]->arg0);
    }
}
void VectorLoop::examine_loop_epilog()
{
    static const int EPILOG_SEARCH_DEPTH = 6; ///< How far to look after the loop
    std::stringstream ss;
    loopBlock->lastOp()->printRaw(ss);
    ghidra::pLogger->info("LastOp: {0:s}", ss.str());
    ss.str("");
    const ghidra::PcodeOp* epiOp = loopBlock->lastOp()->nextOp();
    int opCount = 0;
    epilogPcodes.clear();
    while ((opCount < EPILOG_SEARCH_DEPTH) && (epiOp != nullptr))
    {
        epiOp->printRaw(ss);
        ghidra::pLogger->info("Possible Epilog Pcode: {0:s}", ss.str());
        ss.str("");
        epilogPcodes.push_back(epiOp);
        epiOp = epiOp->nextOp();
        ++opCount;
    }
}

void VectorLoop::collect_related_blocks()
{
    int edgesIn = loopBlock->sizeIn();
    for (int i = 0; i < edgesIn; i++)
    {
        ghidra::FlowBlock* b = loopBlock->getIn(i);
        if (b != loopBlock) relatedBlocks.push_back(b);
    }
}

static std::set<ghidra::intb> loopsAnalyzed;
void VectorLoop::generateReport()
{
    std::stringstream ss;
    auto exists = loopsAnalyzed.find(firstAddr);
    if(exists != loopsAnalyzed.end()) return;
    loopsAnalyzed.insert(firstAddr);
    std::string loopControlStructure;
    if (simpleFlowStructure)
        loopControlStructure = "simple";
    else
        loopControlStructure = "complex";
    reportFile <<
        "Vector Loop (" << loopControlStructure << "):" << std::endl <<
        "\tcontrol structure is " << loopControlStructure << std::endl <<
        std::hex <<
        "\tLoop start address: 0x"<< firstAddr << std::endl <<
        "\tLoop length: 0x" << lastAddr - firstAddr << std::endl <<
        std::dec <<
        "\tsetvli mode: element size=" << elementSize << ", multiplier=" << multiplier << std::endl <<
        "\tvector loads: " << vLoadOps.size() << std::endl <<
        "\tvector stores: " << vStoreOps.size() << std::endl <<
        "\tinteger arithmetic ops: " << sIntegerOps.size() << std::endl <<
        "\tscalar comparisons: " << sComparisonOps.size() << std::endl <<
        "\tvector logical ops: " << vLogicalOps.size() << std::endl <<
        "\tvector integer ops: " << vIntegerOps.size() << std::endl <<
        "\tvector comparisons: " << vComparisonOps.size() << std::endl <<
        "\tvector source operands: " << vSourceOperands.size() << std::endl <<
        "\tvector destination operands: " << vDestinationOperands.size() << std::endl <<
        "\tedges in: " << relatedBlocks.size() << std::endl;
    reportFile << "\tVector instructions (handled | unhandled | epilog): ";
    for (auto vOp: vectorOps)
    {
        ghidra::PcodeOp* op = vOp->op;
        const RiscvUserPcode *vsetInfo = RiscvUserPcode::getUserPcode(*op);
        reportFile << vsetInfo->asmOpcode << ", ";
    }
    reportFile << "| ";
    for (auto vOp: unhandledVectorOps)
    {
        ghidra::PcodeOp* op = vOp->op;
        const RiscvUserPcode *vsetInfo = RiscvUserPcode::getUserPcode(*op);
        reportFile << vsetInfo->asmOpcode << ", ";
    }
    reportFile << "| ";
    bool endEpilog = false;
    // Report on the epilog, trimmed to show at most one unexpected opcode
    for (auto op: epilogPcodes)
    {
        if (endEpilog) break;
        const RiscvUserPcode *vsetInfo = RiscvUserPcode::getUserPcode(*op);
        if (vsetInfo != nullptr) reportFile << vsetInfo->asmOpcode << ", ";
        else
        {
            std::string opChar;
            switch(op->code())
            {
                case ghidra::CPUI_BRANCH:
                case ghidra::CPUI_CBRANCH:
                case ghidra::CPUI_BRANCHIND:
                case ghidra::CPUI_CALL:
                case ghidra::CPUI_RETURN:
                    endEpilog = true;
                    opChar = "?";
                    break;
                case ghidra::CPUI_INT_EQUAL:
                    opChar = "==";
                    break;
                case ghidra::CPUI_INT_NOTEQUAL:
                    opChar = "!=";
                    break;
                case ghidra::CPUI_INT_SLESS:
                case ghidra::CPUI_INT_LESS:
                    opChar = "<";
                    break;
                case ghidra::CPUI_INT_SLESSEQUAL:
                case ghidra::CPUI_INT_LESSEQUAL:
                    opChar = "<=";
                    break;
                case ghidra::CPUI_PTRADD:
                case ghidra::CPUI_INT_ADD:
                    opChar = "+";
                    break;
                case ghidra::CPUI_INT_MULT:
                    opChar = "*";
                    break;
                case ghidra::CPUI_CAST:
                    opChar = "cast";
                    break;
                default:
                    opChar = "?";
                    endEpilog = true;
            }
            reportFile << opChar << ", ";
        }
    }
    reportFile << std::endl;
    if (terminationControl != nullptr)
    {
        terminationControl->printRaw(ss);
        reportFile << "\tLoop control variable: " << ss.str() << std::endl;
        ss.str("");
    }
    reportFile << "\tLoop Local-scope Varnodes: ";
    for (auto vn: loopLocalVns)
    {
        vn->printRaw(ss);
        reportFile << ss.str() << ", ";
        ss.str("");
    }
    reportFile << std::endl;
}

bool VectorLoop::unresolvedDependencies(const ghidra::PcodeOp* result)
{
    bool unresolvedDependencies = false;
    std::stringstream ss;
    ghidra::uintb resultOffset = result->getAddr().getOffset();
    ghidra::pLogger->info("Checking for unresolved dependencies outside of 0x{0:x} to 0x{1:x}",
        firstAddr, resultOffset);
    for (auto vn: loopLocalVns)
    {
        ghidra::inspector->log("\tChecking Varnode:", vn);
        for (auto iter=vn->beginDescend(); iter != vn->endDescend(); ++iter)
        {
            ghidra::PcodeOp* depOp = *iter;
            ghidra::uintb opOffset = depOp->getAddr().getOffset();
            ghidra::inspector->log("\t\tDependent PcodeOp", depOp);
            if ((opOffset < firstAddr) ||
                (opOffset > resultOffset))
            {
                unresolvedDependencies = true;
                ss << "\tlocal varnode: ";
                vn->printRaw(ss);
                ss << "\treferencing pcodeOp: ";
                depOp->printRaw(ss);
                ghidra::pLogger->warn("Unable to complete transform due to reference to loop-local Varnode: {0:s}",
                    ss.str());
                ss.str("");
            }
        }
    }
    ghidra::pLogger->flush();
    return unresolvedDependencies;
}

VectorLoop::~VectorLoop()
{
    for (auto op:vectorOps) delete op;
    for (auto op:unhandledVectorOps) delete op;
    for (auto op:scalarOps) delete op;
    for (auto op: otherScalarOps) delete op;
    for (auto operand: vSourceOperands) delete operand;
    for (auto operand: vDestinationOperands) delete operand;
    for (auto const& [key, val] : registerPhiMapping) delete val;
    registerPhiMapping.clear();
    for (auto const& [key, val] : csRegisterPhiMapping) delete val;
    csRegisterPhiMapping.clear();
}

void VectorEpilogProcessor::setStopSet(const std::set<ghidra::Varnode*>& stopSetParam)
{
    stopSet = stopSetParam;
}

void VectorEpilogProcessor::traceDependencies(const std::set<ghidra::Varnode*>& depSet, const std::string& label)
{
    for (auto vn: depSet)
    {
        vn->printRaw(ss);
        ss << ", ";
    }
    ghidra::pLogger->trace("\t{0:s}: {1:s}", label, ss.str());
    ss.str("");
}

void VectorEpilogProcessor::traceResultCandidates(const std::vector<ghidra::Varnode*>& results, const std::string& label)
{
    for (auto vn: results)
    {
        vn->printRaw(ss);
        ss << ", ";
    }
    ghidra::pLogger->trace("\t{0:s}: {1:s}", label, ss.str());
    ss.str("");
}

/// @brief Several lambda filters are available to filter potential results
typedef std::function<bool(const ghidra::Varnode*)> ResultFilterLambda;

void VectorEpilogProcessor::getIntersectionVector(std::vector<ghidra::Varnode*>& results, const ghidra::Varnode* root1, const ghidra::Varnode* root2)
{
    std::set<ghidra::Varnode*> s1DepSet;
    std::set<ghidra::Varnode*> s2DepSet;

    ResultFilterLambda myFilter;
    switch(resultFilter){
        case REGISTER_VARNODE_ONLY:
            myFilter = selectRegisterVnOnly;
            break;
        case ANY_VARNODE:
            myFilter = selectAny;
            break;
        default:
            ghidra::pLogger->error("Unknown result filter requested");
            return;
    }

    ghidra::inspector->collectDependencies(s1DepSet, root1, stopSet, MAX_DEPENDENCY_DEPTH);
    if (trace) traceDependencies(s1DepSet, "intersection set root1");
    ghidra::inspector->collectDependencies(s2DepSet, root2, stopSet,
        MAX_DEPENDENCY_DEPTH);
        if (trace) traceDependencies(s2DepSet, "intersection set root2");
    // Now compute the intersection, finding common dependencies of our two sources
    std::vector<ghidra::Varnode*> intersection_vector;
    std::set_intersection(
        s1DepSet.begin(), s1DepSet.end(),       // Range 1
        s2DepSet.begin(), s2DepSet.end(),       // Range 2
        std::back_inserter(intersection_vector) // Output iterator
    );
    std::sort(intersection_vector.begin(), intersection_vector.begin(),
        [](const ghidra::Varnode* a, const ghidra::Varnode* b) {
        return a->getDef()->getAddr().getOffset() < b->getDef()->getAddr().getOffset();});
    std::copy_if(intersection_vector.begin(), intersection_vector.end(),
                 std::back_inserter(results),
                 myFilter);
    if (trace) traceResultCandidates(results, "\tPotential result Varnodes: ");
}
}