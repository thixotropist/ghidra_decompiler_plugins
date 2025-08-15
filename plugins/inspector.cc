#include <string>
#include "spdlog/spdlog.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"
#include "inspector.hh"

namespace ghidra{

static void collectSubBlocks(const BlockGraph* bg, std::vector<const FlowBlock*>& list)
{
    for (int i = 0; i < bg->getSize(); i++)
    {
        list.push_back(bg->subBlock(i));
    }
}

Inspector::Inspector(std::shared_ptr<spdlog::logger> myLogger) :
    logger(myLogger)
{
}
void Inspector::log(const string label, const FlowBlock* fb)
{
    logger->trace("Inspect FlowBlock {0:s}", label);
    int edgesIn = fb->sizeIn();
    int edgesOut = fb->sizeOut();
    int flags = fb->getFlags();
    std::vector<const FlowBlock*> list;

    const FlowBlock* parent = nullptr;
    const FlowBlock* immedDom = fb->getImmedDom();
    const FlowBlock* copyMap = fb->getCopyMap();
    FlowBlock::block_type typ = fb->getType();
    string blockType;
    switch(typ)
    {
      case FlowBlock::t_plain:
        blockType = "Plain";
        break;
      case FlowBlock::t_basic:
        blockType = "Basic";
        break;
      case FlowBlock::t_graph:
        blockType = "BlockGraph";
        parent = fb->getParent();
        collectSubBlocks(reinterpret_cast<const BlockGraph*>(fb), list);
        break;
      case FlowBlock::t_copy:
        blockType = "BlockCopy";
        copyMap = nullptr;
        parent = fb->getParent();
        collectSubBlocks(reinterpret_cast<const BlockGraph*>(fb), list);
        break;
      case FlowBlock::t_goto:
        blockType = "BlockGoto";
        parent = fb->getParent();
        collectSubBlocks(reinterpret_cast<const BlockGraph*>(fb), list);
        break;
      case FlowBlock::t_ls:
        blockType = "BlockList";
        parent = fb->getParent();
        collectSubBlocks(reinterpret_cast<const BlockGraph*>(fb), list);
        break;
      case FlowBlock::t_whiledo:
        blockType = "BlockWhileDo";
        parent = fb->getParent();
        collectSubBlocks(reinterpret_cast<const BlockGraph*>(fb), list);
        break;
      case FlowBlock::t_dowhile:
        blockType = "BlockDoWhile";
        parent = fb->getParent();
        collectSubBlocks(reinterpret_cast<const BlockGraph*>(fb), list);
        break;
      default:
        blockType = "Other";
    }
    logger->trace("\tEdgesIn = {0:d}; EdgesOut = {1:d}; List Elements = {2:d}; Flags = 0x{3:x};", 
        edgesIn, edgesOut, list.size(), flags);
    std::stringstream ss;
    if (parent != nullptr)
    {
        parent->printRaw(ss);
        logger->trace("\tparent Flowblock is:\n{0:s}", ss.str());
        ss.str("");
    }
    if (immedDom != nullptr)
    {
        immedDom->printRaw(ss);
        logger->trace("\timmediateDominator is:\n{0:s}", ss.str());
        ss.str("");
    }
    if (copyMap != nullptr)
    {
        copyMap->printRaw(ss);
        logger->trace("\tcopyMap is:\n{0:s}", ss.str());
        ss.str("");
    }
    logger->trace("\tType = {0:s}", blockType);
}
}