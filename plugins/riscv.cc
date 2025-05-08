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

#include "vectorcopy.hh"
#include "diagnostics.hh"
#include "riscv.hh"

static const bool DO_SURVEY = false;  ///< survey the loaded architecture
static const bool SURVEY_USERPCODEOPS = false;  ///< show user pcode ops by name and index
static const int MAX_USER_PCODES = 10000;  ///< limit the number of user pcode ops shown

namespace ghidra {

std::ofstream logFile;

RiscvUserPcode::RiscvUserPcode(const string& op, int index) :
    asmOpcode(op),
    ghidraOp(index)
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
    isLoad = asmOpcode.find("vle", 0) == 0;
    isStore = (asmOpcode.find("vse", 0) == 0) &&
        !(asmOpcode.find("vset", 0) == 0) &&
        !(asmOpcode.find("vsext", 0) == 0);
    isLoadImmediate = asmOpcode.find("vmv_v_i", 0) == 0;
    // fix this, not all userpcode ops are vector ops
    isVectorOp = true;
};

const RiscvUserPcode* RiscvUserPcode::getUserPcode(PcodeOp& op)
{
    if (op.code() != CPUI_CALLOTHER)
        return nullptr;
    if (op.numInput() < 1)
        return nullptr;
    uintb userop_index = op.getIn(0)->getOffset();
    return riscvPcodeMap[userop_index];
}

std::map<int, RiscvUserPcode*> riscvPcodeMap;
std::shared_ptr<spdlog::logger> pluginLogger;
std::shared_ptr<spdlog::logger> loopLogger;

int transformCount;

/**
 * @brief Initialize a sample plugin after ghidra::Architecture::init is executed.
 * @details The binary program should be loaded with no analysis yet performed
 */
extern "C" int plugin_init(void *context)
{
    pluginLogger = spdlog::basic_logger_mt("riscv_vector", "/tmp/ghidraRiscvLogger.log");
    // log levels are trace, debug, info, warn, error and critical.
    pluginLogger->set_level(spdlog::level::trace);
    loopLogger = pluginLogger->clone("vector_loop");
    loopLogger->set_level(spdlog::level::trace);
    transformCount = 0;
    pluginLogger->info("Maximum number of vector transforms: {0:d}", transformCount);
    logFile.open("/tmp/ghidraPluginAnalysis.log");
    logFile << "Initiating plugin analysis log" << std::endl;
    Architecture* arch = reinterpret_cast<Architecture*>(context);
    pluginLogger->info("Plugin initialized");
    // The pcode index identifies the target of a CALLOTHER
    for (int index=0; index<=10000; index++) {
        const UserPcodeOp* op = arch->userops.getOp(index);
        if (op == nullptr) break;
        riscvPcodeMap.insert(std::make_pair(index, new RiscvUserPcode(op->getName(), index)));
    }
    pluginLogger->trace("Found {0} user pcode ops during plugin_init", riscvPcodeMap.size());
    pluginLogger->flush();
    return 0;
}
/**
 * @brief Make new plugin Rules available for the main decompiler
 * 
 */
extern "C" int plugin_getrules(std::vector<Rule*>& rules)
{
    pluginLogger->trace("Adding a new Rule to pluginrules");
    rules.push_back(new RuleVectorCopy("pluginrules"));
    pluginLogger->flush();
    return 1;
}

/**
 * @brief register any new builtins
 * @details access from UserOpManage::registerBuiltin
 */
extern "C" DatatypeUserOp* plugin_registerBuiltin(Architecture* glb, uint4 id)
{
    DatatypeUserOp* res;
    pluginLogger->trace("Entering plugin_registerBuiltin with id=0x{0:x}", id);
    switch(id)
    {
      case VECTOR_MEMCPY:
        {
          pluginLogger->trace("Creating a new DatatypeUserOp");
          int4 ptrSize = glb->types->getSizeOfPointer();
          int4 wordSize = glb->getDefaultDataSpace()->getAddrSize();
          Datatype *vType = glb->types->getTypeVoid();
          Datatype *ptrType = glb->types->getTypePointer(ptrSize,vType,wordSize);
          Datatype *intType = glb->types->getBase(wordSize,TYPE_UINT);
          res = new DatatypeUserOp("vector_memcpy",glb,VECTOR_MEMCPY,vType,ptrType,ptrType,intType);
          pluginLogger->trace("Creation complete");
          break;
        }
      case VECTOR_MEMSET:
      {
        pluginLogger->trace("Creating a new DatatypeUserOp");
        int4 ptrSize = glb->types->getSizeOfPointer();
        int4 wordSize = glb->getDefaultDataSpace()->getAddrSize();
        Datatype *vType = glb->types->getTypeVoid();
        Datatype *ptrType = glb->types->getTypePointer(ptrSize,vType,wordSize);
        Datatype *intType = glb->types->getBase(wordSize,TYPE_UINT);
        res = new DatatypeUserOp("vector_memset",glb,VECTOR_MEMSET,vType,ptrType,intType,intType);
        pluginLogger->trace("Creation complete");
        break;
      }
      default:
        pluginLogger->warn("Unrecognized new DatatypeUserOp");
        res = nullptr;
    }
    pluginLogger->flush();
    return res;
}

/**
 * @brief deallocate any heap allocations
 * 
 */
extern "C" void plugin_exit()
{
    pluginLogger->trace("Exiting the RISC-V transform plugin");
    for (auto p: riscvPcodeMap)
    {
        delete p.second;
    }
    riscvPcodeMap.clear();
    pluginLogger->flush();
}
}