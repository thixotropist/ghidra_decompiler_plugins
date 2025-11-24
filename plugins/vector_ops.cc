/**
 * @file vectorOps.cc
 * @author thixotropist
 * @brief Model RISC-V vector operands
 * @date 2025-10-07
 *
 * @copyright Copyright (c) 2025
 *
 */
#include "framework.hh"
#include "vector_ops.hh"
#include "riscv.hh"

namespace riscv_vector{

VectorOperand::~VectorOperand()
{
    for (auto st: stripes) delete st;
    stripes.clear();
}

static std::vector<std::string> opTypeToString;

void VectorOperand::static_init()
{
    opTypeToString = { "load", "store", "constant", "indexer", "other"};
}

void VectorStripe::setVregister(const ghidra::Varnode* const vn)
{
    vector_register = vn->getOffset();
}

void VectorStripe::setBaseAddr(const ghidra::Varnode* const vn)
{
    pointer_register = vn->getOffset();
}

static std::vector<std::string> operationTypeToString;

void VectorOperation::static_init()
{
    VectorOperand::static_init();
    if (ghidra::pLogger->should_log(spdlog::level::trace)) operationTypeToString = {
        "unknown",
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
        "vector to scalar"
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

static std::map<int, VectorLoop::userPcodeOpHandler> opHandlers;
static std::vector<std::string> fTypeToString;
void VectorLoop::static_init()
{
    VectorOperation::static_init();
        ghidra::pLogger->trace("Adding VectorLoop instruction handlers to opHandlers map");

    // instructions found in many vector stanzas, starting with vector_memcpy
    opHandlers[ghidra::riscvNameToGhidraId["vsetvli_e8m1tama"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vsetvli_e8m1tama instruction handler");
            VectorOperation* vOp = new VectorOperation(OperationType::vectorSetup,
                op);
            loop.vectorOps.push_back(vOp);
        };
    opHandlers[ghidra::riscvNameToGhidraId["vle8_v"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vle8_v instruction handler");
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoad,
                op);
            loop.vectorOps.push_back(vOp);
        };
    opHandlers[ghidra::riscvNameToGhidraId["vse8_v"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vse8_v instruction handler");
            VectorOperation* vOp = new VectorOperation(OperationType::vectorStore,
                op);
            loop.vectorOps.push_back(vOp);
        };
    // instructions found in vector_strlen stanzas
    opHandlers[ghidra::riscvNameToGhidraId["vle8ff_v"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vle8ff_v instruction handler");
            loop.loopFlags |= ghidra::RISCV_VEC_INSN_FAULT_ONLY_FIRST;
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoadFF,
                op);
            loop.vectorOps.push_back(vOp);
        };
    opHandlers[ghidra::riscvNameToGhidraId["vmseq_vi"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vmseq_vi instruction handler");
            // First operand is a vector register, second operand is an integer immediate.
            // Result is a vector register
            VectorOperation* vOp = new VectorOperation(OperationType::vectorImmediateToVector,
                op);
            loop.vectorOps.push_back(vOp);
        };
    opHandlers[ghidra::riscvNameToGhidraId["vfirst_m"]] =
        [](VectorLoop& loop, int a, ghidra::PcodeOp* op) {
            ghidra::pLogger->trace("Invoked vfirst_m instruction handler");
            VectorOperation* vOp = new VectorOperation(OperationType::vectorToScalar,
                op);
            loop.vectorOps.push_back(vOp);
        };
    if (ghidra::pLogger->should_log(spdlog::level::trace))
    {
        fTypeToString = {"memcpy", "memset", "strlen",  "transform",  "reduce",
            "innerProduct", "unknown", "other"};
    }
}
VectorLoop::VectorLoop(const ghidra::Funcdata& dataParam, bool traceParam) :
    terminationConditionFlags(0),
    typ(unknown),
    name("pending"),
    loopFlags(0x0),
    loopFound(false),
    data(dataParam),
    vsetOp(nullptr),
    codeSpace(nullptr),
    loopBlock(nullptr),
    comparisonOp(ghidra::CPUI_MAX),
    simpleFlowStructure(false),
    numElements(nullptr),
    vSliceCount(nullptr),
    vnSrc(nullptr),
    vnDst(nullptr),
    multiplier(0),
    elementSize(0),
    vlReg(0),
    vsReg(0),
    trace(traceParam)
{
}

void VectorLoop::analyze(ghidra::PcodeOp* vsetOp)
{
    examine_control_flow(vsetOp);
    // terminate construction if this vset op doesn't start a loop
    if (!loopFound) return;
    ghidra::pLogger->info("Analyzing potential vector loop stanza at 0x{0:x}",
        firstAddr);
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
    // Summarize key features to a report file
    generateReport();
}

bool VectorLoop::invokeVectorOpHandler(ghidra::PcodeOp* op)
{
    const ghidra::RiscvUserPcode* opInfo = ghidra::RiscvUserPcode::getUserPcode(*op);
    ghidra::pLogger->trace("Looking for instruction handler for {0:s} with id {1:d}",
        opInfo->asmOpcode, opInfo->ghidraOp);
    auto f = opHandlers.find(opInfo->ghidraOp);
    if (f != opHandlers.end())
    {
        ghidra::pLogger->trace("Found the instruction handler, executing:");
        std::function<void(VectorLoop& loop, int ghidraOp, ghidra::PcodeOp* op)> handler = f->second;
        (handler)(*this, opInfo->ghidraOp, op);
        return true;
    }
    else
    {
        ghidra::pLogger->trace("Found no instruction handler, sending to otherVectorOps:");
        otherVectorOps.push_back(new VectorOperation(OperationType::unknown, op));
    }
    return false;
}

bool VectorLoop::isDefinedInLoop(const ghidra::Varnode* vn)
{
    const ghidra::PcodeOp* definingOp = vn->getDef();
    if (definingOp == nullptr) return false;
    ghidra::intb offset = definingOp->getAddr().getOffset();
    bool addressInLoop = (offset >= firstAddr) && (offset <= lastAddr);
    bool blockIsLoopblock = definingOp->getParent() == loopBlock;
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
    firstAddr = vsetOp->getAddr().getOffset();
    loopBlock = vsetOp->getParent();
    lastAddr = loopBlock->getStop().getOffset();
    codeSpace = vsetOp->getAddr().getSpace();
    // Get the Ghidra block containing this loop
    ghidra::PcodeOp* lastOp = loopBlock->lastOp();
    bool isBranch = lastOp->isBranch();
    // this block forms a loop if it starts with a vset and ends
    // with a conditional branch back to the start
    if (isBranch && (lastOp->code() == ghidra::CPUI_CBRANCH))
    {
        ghidra::intb branchTarget = lastOp->getIn(0)->getAddr().getOffset();
        if (branchTarget == firstAddr)
        {
            simpleFlowStructure = true;
            loopFound = true;
        }
        else
        {
            simpleFlowStructure = false;
            loopFound = false;
        }
    }
}

void VectorLoop::collect_phi_nodes()
{
    ghidra::PcodeOpTree::const_iterator iter = data.beginOp(vsetOp->getAddr());
    ghidra::PcodeOpTree::const_iterator enditer = data.endOp(vsetOp->getAddr());
    // This loop collects PcodeOps that share an instruction address
    // with the trigger vsetOp.
    ghidra::pLogger->trace("  Iterating over vset phi pcodes");
    while(iter!=enditer) {
        // iter points at a (SeqNum, PcodeOp*) pair
        ghidra::PcodeOp *op = (*iter).second;
         ++iter;
         if (op->code() == ghidra::CPUI_MULTIEQUAL)
         {
            if (trace)
            {
                std::stringstream ss;
                op->printRaw(ss);
                ghidra::pLogger->trace("  Analysis of Phi node: {0:s}",
                    ss.str());
            }
            int numArgs = op->numInput();
            for (int slot = 0; slot < numArgs; ++slot)
            {
                // where does this arg get written?
                if (trace)
                {
                    std::stringstream ss;
                    op->getIn(slot)->printRaw(ss);
                    ghidra::pLogger->trace("  Analysis of Varnode in slot {0:d}: {1:s}",
                        slot, ss.str());
                }
                ghidra::PcodeOp* definingOp = op->getIn(slot)->getDef();
                if (definingOp != nullptr)
                {
                    ghidra::intb offset = definingOp->getAddr().getOffset();
                    if ((offset >= firstAddr) && (offset <= lastAddr))
                    {
                        // we might want to record the slot number and register
                        phiNodesAffectedByLoop.push_back(op);
                    }
                }
            }
         }
    }
    ghidra::pLogger->trace("  Found {0:d} Phi nodes affected by the loop", phiNodesAffectedByLoop.size());
}

void VectorLoop::examine_loop_pcodeops(const ghidra::BlockBasic* loopBlock)
{
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
            std::stringstream ss;
            op->printRaw(ss);
            ghidra::pLogger->trace("  PcodeOp at 0x{0:x}: {1:s}",
                opOffset, ss.str());
        }
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
          case ghidra::CPUI_CALLOTHER:
            {
                const ghidra::RiscvUserPcode* opInfo = ghidra::RiscvUserPcode::getUserPcode(*op);
                if ((opInfo == nullptr) || (!opInfo->isVectorOp))
                {
                    // may be other builtin pcodes
                    otherUserPcodes.push_back(op);
                }
                else if (opInfo->isVset)
                {
                    ghidra::pLogger->trace("Invoking a VectorLoop instruction handler");
                    invokeVectorOpHandler(op);
                    break;
                }
                else
                {
                    ghidra::pLogger->trace("Invoking a VectorLoop instruction handler");
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
        const ghidra::RiscvUserPcode *vsetInfo = ghidra::RiscvUserPcode::getUserPcode(*op);
        switch(vOp->type)
        {
            case OperationType::vectorSetup:
                multiplier = vsetInfo->multiplier;
                elementSize = vsetInfo->elementSize;
                numElements = vOp->arg0;
                vSliceCount = vOp->result;
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
                const ghidra::RiscvUserPcode *vsetInfo = ghidra::RiscvUserPcode::getUserPcode(*testedOp);
                // very crude determination!
                if (vsetInfo == nullptr)
                    terminationConditionFlags |= TERMINATES_ON_COUNTDOWN;
                else
                    terminationConditionFlags |= TERMINATES_ON_DATA_TEST;
                std::stringstream ss;
                testedOp->printRaw(ss);
                ghidra::pLogger->trace("Comparison target = {0:s}\n\tTermination flags = 0x{1:x}",
                    ss.str(), terminationConditionFlags);
                break;
            }
            case OperationType::conditionalBranch:
                break;
            case OperationType::multiplication:
            case OperationType::addition:
            case OperationType::pointerAddition:
            case OperationType::subtraction:
                sIntegerOps.push_back(op);
                break;
            default:
                break;
        }
    }
    // If we have a single vector load, identify its parameters
    if (vLoadOps.size() == 1)
    {
        vlReg = vLoadOps[0]->result->getAddr().getOffset();
        vnSrc = vLoadOps[0]->arg0;
    }
    // If we have a single vector store, identify its parameters
    if (vStoreOps.size() == 1)
    {
        vsReg = vStoreOps[0]->arg0->getAddr().getOffset();
        vnDst = vStoreOps[0]->arg1;
    }
}

static std::set<ghidra::intb> loopsAnalyzed;
void VectorLoop::generateReport()
{
    auto exists = loopsAnalyzed.find(firstAddr);
    if(exists != loopsAnalyzed.end()) return;
    loopsAnalyzed.insert(firstAddr);
    ghidra::reportFile <<
        "Vector Loop Report" << std::endl <<
        "\tLoop start address: 0x" << std::hex << firstAddr << std::endl <<
        "\tLoop length: 0x" << lastAddr - firstAddr << std::endl <<
        "\tsetvli mode: element size=" << elementSize << ", multiplier=" << multiplier <<
        ", vector load register=" << vlReg <<
        ", vector store register=" << vsReg << std::endl <<
        "\tvector loads: " << vLoadOps.size() << std::endl <<
        "\tvector stores: " << vStoreOps.size() << std::endl <<
        "\tcomparisons: " << sComparisonOps.size() << std::endl <<
        "\tinteger arithmetic ops: " << sIntegerOps.size() << std::endl;
    ghidra::reportFile << "\tVector instructions (handled): ";
    for (auto vOp: vectorOps)
    {
        ghidra::PcodeOp* op = vOp->op;
        const ghidra::RiscvUserPcode *vsetInfo = ghidra::RiscvUserPcode::getUserPcode(*op);
        ghidra::reportFile << vsetInfo->asmOpcode << ", ";
    }
    ghidra::reportFile << std::endl;
    ghidra::reportFile << "\tVector instructions (unhandled): ";
    for (auto vOp: otherVectorOps)
    {
        ghidra::PcodeOp* op = vOp->op;
        const ghidra::RiscvUserPcode *vsetInfo = ghidra::RiscvUserPcode::getUserPcode(*op);
        ghidra::reportFile << vsetInfo->asmOpcode << ", ";
    }
    ghidra::reportFile << std::endl;
}

VectorLoop::~VectorLoop()
{
    for (auto op:vectorOps)
    {
        delete op;
    }
    for (auto op:scalarOps)
    {
        delete op;
    }
}
}