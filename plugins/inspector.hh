#ifndef INSPECTOR_HH_
#define INSPECTOR_HH_

#include "spdlog/spdlog.h"

/**
 * @brief Inspect Ghidra objects relevant to graph editing
 * 
 */
namespace ghidra{

class Inspector{
  public:
    std::shared_ptr<spdlog::logger> logger;
    Inspector(std::shared_ptr<spdlog::logger> myLogger);
    void log(const string label, const FlowBlock* fb); ///< log fb details
};

}
#endif /* INSPECTOR_HH_ */