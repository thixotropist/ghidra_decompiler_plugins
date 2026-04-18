#ifndef INSPECTOR_HH_
#define INSPECTOR_HH_

#include "spdlog/spdlog.h"

/**
 * @file inspector.hh
 */
namespace ghidra{
/**
 * @brief Inspect Ghidra objects relevant to graph editing
 */
class Inspector
{
  public:
    /**
     * @brief Construct a new Inspector object
     * @param myLogger the SPDLOG instance used for output
     */
    explicit Inspector(std::shared_ptr<spdlog::logger> myLogger);
    /**
     * @brief Log a single FlowBlock
     * @param label a descriptive string for the FlowBlock's context
     * @param fb the FlowBlock to be logged
     */
    void log(const string label, const FlowBlock* fb);
    /**
     * @brief Log a single PcodeOp
     * @param label a descriptive string for the PcodeOp's context
     * @param op the Opcode to be logged
     */
    void log(const string label, const PcodeOp* op);
    /**
     * @brief Log a single Varnode
     * @param label a descriptive string for the Varnode's context
     * @param vn the Varnode to be logged
     */
    void log(const string label, const Varnode* vn);
    /**
     * @brief Log a single Varnode with slot identifier
     * @param label a descriptive string for the Varnode's context
     * @param vn the Varnode to be logged
     * @param slot the slot in which this Varnode was found
     */
    void log(const string label, const Varnode* vn, int slot);
    /**
     * @brief Collect dependency set of a given Varnode
     * @details Collect dependent varnodes found within a given space
     * @param result The set of dependent Varnodes found
     * @param root The Varnode to start the dependent search
     * @param stopSet Varnodes we don't want to descend from
     * @param maxDepth The maximum length of any dependency chain
     */
    static void collectDependencies(std::set<Varnode*>& result, const Varnode* root,
      const std::set<Varnode*>& stopSet, int maxDepth);
    /**
     * @brief Log the current ActionDatabase
     */
    void logActions();
  private:
    std::shared_ptr<spdlog::logger> logger;     ///< the SPDLOG logger to use for output
    bool logBlockStructure = true;             ///< if true, log full blocks during any blockgraph edits
};
}
#endif /* INSPECTOR_HH_ */