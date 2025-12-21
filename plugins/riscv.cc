#include <iostream>
#include <utility>
#include <fstream>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/capability.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_arch.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/action.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

#include "riscv.hh"
#include "rule_vector_transform.hh"
#include "vector_ops.hh"

static const bool DO_SURVEY = false;  ///< survey the loaded architecture
static const bool SURVEY_USERPCODEOPS = false;  ///< show user pcode ops by name and index
static const int MAX_USER_PCODES = 10000;  ///< limit the number of user pcode ops shown

namespace riscv_vector
{
int transformCountNonLoop; /// Maximum number of non-loop transforms to complete
int transformCountLoop;    /// Maximum number of loop transforms to complete
RiscvUserPcode::RiscvUserPcode(const std::string& op, int index) :
    asmOpcode(op),
    ghidraOp(index),
    flags(0),
    isFaultOnlyFirst(false)
{
    isVseti = asmOpcode.find("vsetivli_", 0) == 0;
    isVset = asmOpcode.find("vsetvli_", 0) == 0;
    if (isVseti || isVset)
    {
        if (asmOpcode.find("e8") != std::string::npos)
            elementSize = 1;
        else if (asmOpcode.find("e16") != std::string::npos)
            elementSize = 2;
        else if (asmOpcode.find("e32") != std::string::npos)
            elementSize = 4;
        else if (asmOpcode.find("e64") != std::string::npos)
            elementSize = 8;
        if ((asmOpcode.find("m1") != std::string::npos) ||
            (asmOpcode.find("mf") != std::string::npos))
            multiplier = 1;
        else if (asmOpcode.find("m2") != std::string::npos)
            multiplier = 2;
        else if (asmOpcode.find("m4") != std::string::npos)
            multiplier = 4;
        else if (asmOpcode.find("m8") != std::string::npos)
            multiplier = 8;
    }
    // Is this a basic vector load operation?
    isLoad = (asmOpcode.find("vle", 0) == 0) &&
        !(asmOpcode.find("vle8ff_v", 0) == 0);
        // Is this a basic vector store operation?
    isStore = (asmOpcode.find("vse", 0) == 0) &&
        !(asmOpcode.find("vset", 0) == 0) &&
        !(asmOpcode.find("vsext", 0) == 0);
    isLoadImmediate = asmOpcode.find("vmv_v_i", 0) == 0;
    // fix this, not all userpcode ops are vector ops
    isMaskSet = (asmOpcode.find("vms", 0) == 0) &&
                (asmOpcode.find("_vi", 4) != std::string::npos);
    isVectorOp = true;
};

const RiscvUserPcode* RiscvUserPcode::getUserPcode(const ghidra::PcodeOp& op)
{
    if (op.code() != ghidra::CPUI_CALLOTHER)
        return nullptr;
    if (op.numInput() < 1)
        return nullptr;
    ghidra::uintb userop_index = op.getIn(0)->getOffset();
    return riscvPcodeMap[userop_index];
}

std::map<int, riscv_vector::RiscvUserPcode*> riscvPcodeMap;      /// lookup a user pcode given Ghidra's sleigh index
std::map<std::string, ghidra::uintb> riscvNameToGhidraId;
std::ofstream reportFile; /// A file holding summary data for each possible vector stanza
}
namespace ghidra
{
Architecture* arch;        /// The Ghidra architecture object for this program
AddrSpace* registerAddrSpace; /// The address space holding RISCV registers
std::shared_ptr<spdlog::logger> pLogger; /// An SPDLOG logger usable by this plugin
/**
 * @brief Initialize a sample plugin after ghidra::Architecture::init is executed.
 * @details The binary program should be loaded with no analysis yet performed.
 * Ghidra's GUI will sometimes start multiple decompilers running in parallel,
 * so we append the process ID to logfile and summaries file names.
 */
extern "C" int plugin_init(void *context)
{
    std::string logFile = "/tmp/ghidraRiscvLogger_" + std::to_string(getpid()) + ".log";
    pLogger = spdlog::basic_logger_mt("riscv_vector", logFile);
    // log levels are trace, debug, info, warn, error and critical.
    pLogger->set_level(spdlog::level::info);
    std::string summariesFilename = "/tmp/riscv_summaries_" + std::to_string(getpid()) + ".txt";
    riscv_vector::reportFile.open(summariesFilename);
    riscv_vector::reportFile << "RISC-V Summary Report" << std::endl;
    riscv_vector::transformCountNonLoop = 0;
    riscv_vector::transformCountLoop = 0;
    pLogger->info("Maximum number of vector transforms:\tloop: 0x{0:x}, non-loop: 0x{1:x})",
        riscv_vector::TRANSFORM_LIMIT_LOOPS, riscv_vector::TRANSFORM_LIMIT_NONLOOPS);
    arch = reinterpret_cast<Architecture*>(context);
    registerAddrSpace = arch->getSpaceByName("register");
    pLogger->info("Plugin framework initialized");
    // The pcode index identifies the target of a CALLOTHER
    for (int index=0; index<=MAX_USER_PCODES; index++) {
        const UserPcodeOp* op = arch->userops.getOp(index);
        if (op == nullptr) break;
        riscv_vector::riscvPcodeMap.insert(std::make_pair(index, new riscv_vector::RiscvUserPcode(op->getName(), index)));
        riscv_vector::riscvNameToGhidraId.insert(std::make_pair(op->getName(), index));
    }
    pLogger->trace("Found {0} user pcode ops during plugin_init", riscv_vector::riscvPcodeMap.size());
    // handle any static initializers
    riscv_vector::VectorLoop::static_init();
    pLogger->info("Plugin RISC-V Vector support initialized");
    pLogger->flush();
    return 0;
}
/**
 * @brief Make new plugin Rules available for the main decompiler
 */
extern "C" int plugin_getrules(std::vector<Rule*>& rules)
{
    pLogger->trace("Adding a new Rule to pluginrules");
    rules.push_back(new riscv_vector::RuleVectorTransform("pluginrules"));
    pLogger->flush();
    return 1;
}

/**
 * @brief register any new builtins
 * @details access from UserOpManage::registerBuiltin
 */
extern "C" DatatypeUserOp* plugin_registerBuiltin(Architecture* glb, uint4 id)
{
    DatatypeUserOp* res;
    pLogger->trace("Entering plugin_registerBuiltin with id=0x{0:x}", id);
    pLogger->trace("Creating a new DatatypeUserOp");
    int4 ptrSize = glb->types->getSizeOfPointer();
    int4 wordSize = glb->getDefaultDataSpace()->getAddrSize();
    // define some common parameter types
    Datatype *vType = glb->types->getTypeVoid();
    Datatype *charType = glb->types->getTypeChar(1);
    Datatype *ptrType = glb->types->getTypePointer(ptrSize, vType, wordSize);
    Datatype *uintType = glb->types->getBase(wordSize, TYPE_UINT);
    Datatype *charPtrType = glb->types->getTypePointer(ptrSize, charType, wordSize);
    switch(id)
    {
    case riscv_vector::VECTOR_MEMCPY:
    {
        res = new DatatypeUserOp("vector_memcpy", glb, riscv_vector::VECTOR_MEMCPY, vType, ptrType, ptrType, uintType);
        pLogger->trace("Creation complete");
        break;
    }
    case riscv_vector::VECTOR_MEMSET:
    {
        res = new DatatypeUserOp("vector_memset", glb, riscv_vector::VECTOR_MEMSET, vType, ptrType, uintType, uintType);
        pLogger->trace("Creation complete");
        break;
    }
    case riscv_vector::VECTOR_STRLEN:
    {
        res = new DatatypeUserOp("vector_strlen", glb, riscv_vector::VECTOR_STRLEN, uintType, charPtrType);
        pLogger->trace("Creation complete");
        break;
    }
    default:
        pLogger->warn("Unrecognized new DatatypeUserOp");
        res = nullptr;
    }
    pLogger->flush();
    return res;
}

/**
 * @brief deallocate any heap allocations
 */
extern "C" void plugin_exit()
{
    pLogger->trace("Exiting the RISC-V transform plugin");
    for (auto p: riscv_vector::riscvPcodeMap)
    {
        delete p.second;
    }
    riscv_vector::riscvPcodeMap.clear();
    pLogger->flush();
    riscv_vector::reportFile.close();
}
}