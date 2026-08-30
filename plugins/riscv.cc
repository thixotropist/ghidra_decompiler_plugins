/**
 * @file riscv.cc
 * @brief Provide the basic RISC-V plugin methods.
 */

#include <iostream>
#include <utility>
#include <fstream>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/type.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/capability.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_arch.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/address.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/space.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/action.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

#include "riscv.hh"
#include "inspector.hh"
#include "action_prepare.hh"
#include "rule_vector_transform.hh"
#include "riscv_sleigh.hh"
#include "user_pcode.hh"
#include "vector_ops.hh"

static const bool DO_SURVEY = false;  ///< survey the loaded architecture
static const bool SURVEY_USERPCODEOPS = false;  ///< show user pcode ops by name and index
static const int MAX_USER_PCODES = 10000;  ///< limit the number of user pcode ops shown

static const spdlog::level::level_enum LOG_LEVEL = spdlog::level::warn; ///< default log level to use

namespace riscv_vector
{
int transformCountNonLoop; ///<@brief Maximum number of non-loop transforms to complete
int transformCountLoop;    ///<@brief Maximum number of loop transforms to complete

std::ofstream reportFile;
std::ofstream strlenSampleFile;
std::ofstream strcmpSampleFile;

}
namespace ghidra
{
Architecture* arch;        ///< The Ghidra architecture object for this program
AddrSpace* registerAddrSpace; ///< The address space holding RISCV registers
AddrSpace* uniqueAddrSpace; ///< The address space holding internal temporaries
AddrSpace* ramAddrSpace; ///< The address space for static RAM variables
AddrSpace* stackAddrSpace; ///< The address space for stack variables
std::shared_ptr<spdlog::logger> pLogger; ///< An SPDLOG logger usable by this plugin
bool trace;                              ///< logger level trace is enabled
bool info;                               ///< logger level info is enabled
std::shared_ptr<Inspector> inspector; ///< Inspector collects probes into Ghidra decompiler internals

/**
 * @brief Initialize a sample plugin after ghidra::Architecture::init is executed.
 * @details The binary program should be loaded with no analysis yet performed.
 * Ghidra's GUI will sometimes start multiple decompilers running in parallel,
 * so we append the process ID to logfile and summaries file names.
 */
extern "C" int plugin_init(void *context)
{
    // prepare a logger to handle processor-specific Rules
    std::string logFile = "/tmp/ghidraRiscvLogger_" + std::to_string(getpid()) + ".log";
    pLogger = spdlog::basic_logger_mt("riscv_vector", logFile);
    // log levels are trace, debug, info, warn, error and critical.
    pLogger->set_level(LOG_LEVEL);
    trace = pLogger->should_log(spdlog::level::trace);
    info = pLogger->should_log(spdlog::level::info);
    pLogger->info("Logging system initialized");
    inspector = std::make_shared<Inspector>(pLogger);
    // log levels are trace, debug, info, warn, error and critical.
    pLogger->info("Ghidra inspector initialized");
    std::string pidAsString = std::to_string(getpid());
    std::string summariesFilename = "/tmp/riscv_summaries_" + pidAsString + ".txt";
    riscv_vector::reportFile.open(summariesFilename);
    riscv_vector::reportFile << "RISC-V Summary Report" << std::endl;
    if (riscv_vector::COLLECT_STRLEN_SAMPLES)
    {
        std::string fn = "/tmp/vector_strlen_summaries_" + pidAsString + ".txt";
        riscv_vector::strlenSampleFile.open(fn);
    }
    if (riscv_vector::COLLECT_STRCMP_SAMPLES)
    {
        std::string fn = "/tmp/vector_strcmp_summaries_" + pidAsString + ".txt";
        riscv_vector::strcmpSampleFile.open(fn);
    }
    riscv_vector::transformCountNonLoop = 0;
    riscv_vector::transformCountLoop = 0;
    pLogger->info("Maximum number of vector transforms:\tloop: 0x{0:x}, non-loop: 0x{1:x})",
        riscv_vector::TRANSFORM_LIMIT_LOOPS, riscv_vector::TRANSFORM_LIMIT_NONLOOPS);
    arch = reinterpret_cast<Architecture*>(context);
    registerAddrSpace = arch->getSpaceByName("register");
    uniqueAddrSpace = arch->getSpaceByName("unique");
    ramAddrSpace = arch->getSpaceByName("ram");
    stackAddrSpace = arch->getSpaceByName("stack");
    pLogger->info("Plugin framework initialized");
    // build database of RISC-V vector instructions
    // riscvNameToPcodeMap will provide mapping from instruction name to instruction handler
    riscv_vector::RiscvUserPcode::loadAsmOpcodes();
    pLogger->info("RiscvUserPcode handlers initialized");
    // The pcode index identifies the target of a CALLOTHER
    for (uintb index=0; index<=MAX_USER_PCODES; index++) {
        const UserPcodeOp* op = arch->userops.getOp(index);
        if (op == nullptr) break;
        std::string opName = op->getName();
        riscv_vector::RiscvUserPcode* code = riscv_vector::riscvNameToPcodeMap[opName];
        if (code != nullptr)
        {
            riscv_vector::riscvPcodeMap.insert(std::make_pair(index, code));
            riscv_vector::riscvNameToGhidraId.insert(std::make_pair(opName, index));
        }
        if (SURVEY_USERPCODEOPS)
        {
            std::cout << "\"" << op->getName() << "\", ";
        }
    }

    // handle any static initializers
    riscv_vector::VectorLoop::static_init();
    riscv_vector::ActionPluginPrepare::static_init();
    pLogger->info("Plugin RISC-V Vector support initialized");
    pLogger->flush();
    return 0;
}

/**
 * @brief Make new plugin Actions available for the main decompiler
 */
extern "C" int plugin_getactions(std::vector<Action*>& actions)
{
    pLogger->trace("Adding new Actions to pluginrules");
    actions.push_back(new riscv_vector::ActionPluginPrepare("pluginrules"));
    // load definitions specific to a given SLEIGH definition file
    ghidra::riscv_sleigh_init(arch);
    if (trace)
    {
        std::stringstream ss;
        ghidra::riscv_sleigh_inspect(arch, ss);
        pLogger->trace("{0:s}", ss.str());
    }
    return 1;
}

/**
 * @brief Make new plugin Rules available for the main decompiler
 */
extern "C" int plugin_getrules(std::vector<Rule*>& rules)
{
    pLogger->info("Inspecting sleigh-dependencies");
    pLogger->trace("Adding new Rules to pluginrules");
    rules.push_back(new riscv_vector::RuleVectorTransform("pluginrules"));
    pLogger->flush();
    return 1;
}

static bool runSurvey = true;
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
    int4 wordSize = ptrSize;
    // define some common parameter types
    Datatype *vType = glb->types->getTypeVoid();
    Datatype *charType = glb->types->getTypeChar(1);
    Datatype *ptrType = glb->types->getTypePointer(ptrSize, vType, wordSize);
    Datatype *uintType = glb->types->getBase(wordSize, TYPE_UINT);
    Datatype *intType = glb->types->getBase(wordSize, TYPE_INT);
    Datatype *charPtrType = glb->types->getTypePointer(ptrSize, charType, wordSize);
    switch(id)
    {
    case riscv_vector::VECTOR_MEMCPY:
    {
        res = new DatatypeUserOp("vector_memcpy", glb, riscv_vector::VECTOR_MEMCPY, vType, ptrType, ptrType, uintType);
        break;
    }
    case riscv_vector::VECTOR_MEMSET:
    {
        res = new DatatypeUserOp("vector_memset", glb, riscv_vector::VECTOR_MEMSET, vType, ptrType, uintType, uintType);
        break;
    }
    case riscv_vector::VECTOR_STRLEN:
    {
        res = new DatatypeUserOp("vector_strlen", glb, riscv_vector::VECTOR_STRLEN, uintType, charPtrType);
        break;
    }
    case riscv_vector::VECTOR_STRCMP:
    {
        res = new DatatypeUserOp("vector_strcmp", glb, riscv_vector::VECTOR_STRCMP, intType, charPtrType, charPtrType);
        break;
    }
    case riscv_vector::VECTOR_STRNCMP:
    {
        res = new DatatypeUserOp("vector_strncmp", glb, riscv_vector::VECTOR_STRNCMP, intType, charPtrType, charPtrType, uintType);
        break;
    }
    default:
        pLogger->warn("Unrecognized new DatatypeUserOp: 0x{0:x}", id);
        res = nullptr;
    }
    // Optionally run some survey code exactly once, after Ghidra has initialized all of its
    // internals.
    if (riscv_vector::SURVEY_ACTION_DATABASE && runSurvey)
    {
        inspector->logActions();
        runSurvey = false;
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
    riscv_vector::RiscvUserPcode::staticCleanup();
    pLogger->flush();
    riscv_vector::reportFile.close();
    if (riscv_vector::COLLECT_STRLEN_SAMPLES)
        riscv_vector::strlenSampleFile.close();
    if (riscv_vector::COLLECT_STRCMP_SAMPLES)
        riscv_vector::strcmpSampleFile.close();
}
}