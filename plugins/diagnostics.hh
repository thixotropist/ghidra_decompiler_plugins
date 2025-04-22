#ifndef __DIAGNOSTICS_HH__
#define __DIAGNOSTICS_HH__

#include "Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"

namespace ghidra {

/**
 * @brief Logging file, usually directed to "/tmp/..."
 */
extern std::ofstream logFile;
/**
 * @brief display a PcodeOp to the Logging file
 * 
 * @param p A Ghidra PcodeOp reference
 * @param label A string describing the context for this PcodeOp
 * @param descend A flag requesting a deep display of any output varnode descendents(readers)
 */
extern void displayPcodeOp(PcodeOp& p, const std::string& label, bool descend);
/**
 * @brief dump the varnode tree for this entire function
 * @details not very useful in practice, although it does provide
 * some explicit type information
 * 
 * @param data The FuncData object holding the function's contextual data
 */
extern void displayVarnodeTree(Funcdata& data);
/**
 * @brief send a string to the logfile
 * 
 * @param comment the string to send
 */
extern void displayComment(const char* comment);
}

#endif /* DIAGNOSTICS */