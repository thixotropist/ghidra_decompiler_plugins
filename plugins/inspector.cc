#include <string>
#include "spdlog/spdlog.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"
#include "framework.hh"
#include "inspector.hh"

namespace ghidra{

Inspector::Inspector(std::shared_ptr<spdlog::logger> myLogger) :
    logger(myLogger)
{
}
void Inspector::logActions()
{
  ActionDatabase* allacts = &arch->allacts;
  Action* root = allacts->getCurrent();
  std::stringstream ss;
  root->printStatistics(ss);
  logger->info("Action Database statistics: {0:s}",
    ss.str());
}
void Inspector::log(const string label, const FlowBlock* fb)
{
    int edgesIn = fb->sizeIn();
    int edgesOut = fb->sizeOut();
    int flags = fb->getFlags();
    std::vector<const FlowBlock*> list;
    const bool SHOW_DOMINATOR = false;
    const FlowBlock* parent = nullptr;
    const FlowBlock* immedDom = fb->getImmedDom();
    const FlowBlock* copyMap = nullptr;
    FlowBlock::block_type typ = fb->getType();
    string blockType;
    switch(typ)
    {
      case FlowBlock::t_plain:
        blockType = "Plain";
        break;
      case FlowBlock::t_basic:
        blockType = "Basic";
        copyMap = fb->getCopyMap();
        break;
      case FlowBlock::t_graph:
        {
          blockType = "BlockGraph";
          parent = fb->getParent();
          BlockGraphEditor bgEditor = BlockGraphEditor(dynamic_cast<const BlockGraph&>(*fb));
          bgEditor.collectSubBlocks(list);
        }
        break;
      case FlowBlock::t_copy:
        blockType = "BlockCopy";
        copyMap = nullptr;
        parent = fb->getParent();
        break;
      case FlowBlock::t_goto:
        {
          // Goto targets aren't considered subblocks, so we collect any such independently
          blockType = "BlockGoto";
          parent = fb->getParent();
          const BlockGoto* blkGt = dynamic_cast<const BlockGoto*>(fb);
          BlockGraphEditor bgEditor = BlockGraphEditor(*blkGt);
          bgEditor.collectSubBlocks(list);
          FlowBlock* gotoTarget = blkGt->getGotoTarget();
          if (gotoTarget != nullptr) list.push_back(gotoTarget);
        }
        break;
      case FlowBlock::t_if:
        {
          // Goto targets within BlockIfs aren't considered subblocks, so we collect any such independently
            blockType = "BlockIf";
            parent = fb->getParent();
            const BlockIf* blkIf = dynamic_cast<const BlockIf*>(fb);
            BlockGraphEditor bgEditor = BlockGraphEditor(*blkIf);
            bgEditor.collectSubBlocks(list);
            FlowBlock* gotoTarget = blkIf->getGotoTarget();
            if (gotoTarget != nullptr) list.push_back(gotoTarget);
        }
        break;
      case FlowBlock::t_ls:
        {
          blockType = "BlockList";
          parent = fb->getParent();
          BlockGraphEditor bgEditor = BlockGraphEditor(dynamic_cast<const BlockGraph&>(*fb));
          bgEditor.collectSubBlocks(list);
        }
        break;
      case FlowBlock::t_whiledo:
      {
        blockType = "BlockWhileDo";
        parent = fb->getParent();
        BlockGraphEditor bgEditor = BlockGraphEditor(dynamic_cast<const BlockGraph&>(*fb));
        bgEditor.collectSubBlocks(list);
      }
        break;
      case FlowBlock::t_dowhile:
      {
        blockType = "BlockDoWhile";
        parent = fb->getParent();
        BlockGraphEditor bgEditor = BlockGraphEditor(dynamic_cast<const BlockGraph&>(*fb));
        bgEditor.collectSubBlocks(list);
      }
        break;
      default:
        blockType = "Other";
    }
    logger->trace("Inspect FlowBlock {0:s} of type {1:s}", label, blockType);
    logger->trace("\tEdgesIn = {0:d}; EdgesOut = {1:d}; List Elements = {2:d}; Flags = 0x{3:x};",
        edgesIn, edgesOut, list.size(), flags);
    std::stringstream ss;
    if (parent != nullptr)
    {
        parent->printRaw(ss);
        logger->trace("\tparent Flowblock is:\n{0:s}", ss.str());
        ss.str("");
    }
    if (SHOW_DOMINATOR && (immedDom != nullptr))
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
}
}