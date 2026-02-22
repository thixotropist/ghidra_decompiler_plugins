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
  std::shared_ptr<spdlog::logger> logger;     ///< the SPDLOG logger to use for output
  public:
    /**
     * @brief Construct a new Inspector object
     * @param myLogger the SPDLOG instance used for output
     */
    explicit Inspector(std::shared_ptr<spdlog::logger> myLogger);
    /**
     * @brief Inspect a single FlowBlock
     *
     * @param label a descriptive string for the FlowBlock's context
     * @param fb the FlowBlock to be logged
     */
    void log(const string label, const FlowBlock* fb); /// log fb details
    /**
     * @brief Log the current ActionDatabase
     */
    void logActions();
};
}
#endif /* INSPECTOR_HH_ */