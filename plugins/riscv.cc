#include <iostream>
#include <utility>
#include <fstream>

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/capability.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_arch.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/action.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh"

#include "vectorcopy.hh"

static const bool DO_SURVEY = false;  ///< survey the loaded architecture
static const bool SURVEY_USERPCODEOPS = false;  ///< show user pcode ops by name and index
static const int MAX_USER_PCODES = 10000;  ///< limit the number of user pcode ops shown

namespace ghidra {

static const bool DO_TRACING = false;
std::ofstream logFile;

/// @brief user ops we are interested in
std::vector<std::string> userops = {
    "vsetvli_e8m8tama",
    "vsetivli_e8m8tama",
    "vsetvli_e8m1tama",
    "vsetivli_e8m1tama",
    "vsetivli_e8mf2tama",
    "vsetivli_e8mf4tama",
    "vsetivli_e8mf8tama",
    "vle8_v",
    "vse8_v"
};

/**
 * @brief Map RISC-V user pcodeop names to pointers to those operations
 */
std::map<std::string, UserPcodeOp*>userOpMap;

/**
 * @brief Generate the static userops map
 * 
 * @param mgr 
 */
void buildUserPcodeMap(UserOpManage& mgr)
{
    for (const std::string& s : userops)
    {
        UserPcodeOp* op = mgr.getOp(s);
        if (op == nullptr) {
            logFile << "Failed to find the user pcode op for " << s << std::endl;
        }
        userOpMap.insert(std::pair<std::string, UserPcodeOp*>(s, op));
    }
}

/**
 * @brief Initialize a sample plugin after ghidra::Architecture::init is executed.
 * @details The binary program should be loaded with no analysis yet performed
 */
extern "C" int plugin_init(void *context)
{
    logFile.open("/tmp/ghidraPlugin.log");
    Architecture* arch = reinterpret_cast<Architecture*>(context);
    logFile << "Plugin initialized" << std::endl;
    logFile.flush();
    buildUserPcodeMap(arch->userops);
    // save the current Architecture object
    if (DO_TRACING)
        logFile << "UserPcodeMap created with " << userOpMap.size() << " significant user pcode ops" << std::endl;
    // Optionally list all user pcode names with their internal indices - there are over 1200 of them.
    // The pcode index identifies the target of a CALLOTHER
    if (DO_SURVEY & SURVEY_USERPCODEOPS) {
        logFile << "User pcodeops:"<< std::endl;
        int count = 0;
        for (int i=0; i<=10000; i++) {
            const UserPcodeOp* op = arch->userops.getOp(i);
            if (op == nullptr) break;
            logFile << i << "  :" << op->getName() << "(0x" << \
                std::hex << op->getIndex() << ")" << std::dec << std::endl;
            count++;
        }
        logFile << "Found " << count << " user pcode ops during plugin_init" << std::endl;
    }
    return 0;
}
/**
 * @brief Make new plugin Rules available for the main decompiler
 * 
 */
extern "C" int plugin_getrules(std::vector<Rule*>& rules)
{
    rules.push_back(new RuleVectorCopy("pluginrules"));
    return 1;
}
}