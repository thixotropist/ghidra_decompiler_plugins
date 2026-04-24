#include <string>
#include <set>
#include <stack>
#include "spdlog/spdlog.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/block.hh"
#include "framework.hh"
#include "inspector.hh"

namespace ghidra{

Inspector::Inspector(std::shared_ptr<spdlog::logger> myLogger) :
    logger(myLogger)
{
  logger->trace("Ghidra Inspector initialized");
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
void Inspector::log(const string& label, const FlowBlock* fb)
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
    if (logBlockStructure && (parent != nullptr))
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
    if (logBlockStructure && (copyMap != nullptr))
    {
        copyMap->printRaw(ss);
        logger->trace("\tcopyMap is:\n{0:s}", ss.str());
        ss.str("");
    }
}
void Inspector::log(const string& label, const PcodeOp* op)
{
  std::stringstream ss;
  if (op == nullptr)
    logger->warn("{0:s}: PCodeOp* is null!", label);
  else
  {
    op->printRaw(ss);
    logger->trace("{0:s}: {1:s} at 0x{2:x}", label, ss.str(), op->getAddr().getOffset());
    ss.str("");
  }
}
void Inspector::log(const string& label, const Varnode* vn)
{
  std::stringstream ss;
  if (vn == nullptr)
    logger->warn("{0:s}: Varnode* is null!", label);
  else
  {
    vn->printRaw(ss);
    logger->trace("{0:s}: {1:s}", label, ss.str());
    ss.str("");
  }
}
void Inspector::log(const string& label, const Varnode* vn, int slot)
{
  std::stringstream ss;
  if (vn == nullptr)
    logger->warn("{0:s}: Varnode* is null!", label);
  else
  {
    vn->printRaw(ss);
    logger->trace("{0:s}, slot {1:d}: {2:s}", label, slot, ss.str());
    ss.str("");
  }
}

void Inspector::collectDependencies(std::set<Varnode*>& result, const Varnode* root,
      const std::set<Varnode*>& stopSet, int maxDepth)
{
    std::stack<ghidra::Varnode*> candidateVns;
    std::set<ghidra::Varnode*> visitedVns = stopSet;
    std::set<ghidra::PcodeOp*> visitedOps;

    const ghidra::Varnode* vn = root;
    int count = 0;
    while ((vn != nullptr) && (count++ < maxDepth))
    {
        for (auto iter=vn->beginDescend(); iter != vn->endDescend(); ++iter)
        {
            ghidra::PcodeOp* op = (*iter);
            if (visitedOps.count(op) > 0)
                continue;
            visitedOps.insert(op);
            ghidra::Varnode* vnext = op->getOut();
            if ((vnext == nullptr) || visitedVns.count(vnext) != 0)
                continue;
            result.insert(vnext);
            candidateVns.push(vnext);
        }
        if (candidateVns.empty())
        {
            vn = nullptr;
        }
        else
        {
            vn = candidateVns.top();
            candidateVns.pop();
        }
    }
}
void Inspector::auditVarnodes(const ghidra::Funcdata& data, std::ofstream& ss)
{
  // free varnodes are not necessarily errors if found on this listing
  VarnodeLocSet::const_iterator startiter;
  for(startiter=data.beginLoc();startiter!=data.endLoc();++startiter)
  {
    ghidra::Varnode* vn = *startiter;
    std::uintptr_t ptr_as_int = reinterpret_cast<std::uintptr_t>(vn);
    ss << "0x" << std::hex << ptr_as_int << "\t";
    vn->printRaw(ss);
    ss << std::endl;
  }
}
void Inspector::auditBlockGraph(const ghidra::Funcdata& data, std::ofstream& ss)
{
  ss << "Auditing this function's Basic BlockGraph" << std::endl;
  const ghidra::BlockGraph& graph = data.getBasicBlocks();
  const std::vector<FlowBlock*>& blocks = graph.getList();
  int level = 1;
  for (const auto bl: blocks)
  {
    auditBlockGraph(bl, ss, level);
  }
  ss << "Auditing this function's Structure BlockGraph" << std::endl;
  const ghidra::BlockGraph& controlGraph = data.getStructure();
  controlGraph.printTree(ss, 0);
}

void Inspector::auditBlockGraph(const ghidra::FlowBlock* bl, std::ofstream& ss, int level)
{
    std::stringstream padding;
    for (int i = 0; i < level; i++)
      padding << " ";
    ss << padding.str() << "Block #" << bl->getIndex() << std::endl;
    ss << padding.str() << "\tEdges in, out: " << bl->sizeIn() << ", " << bl->sizeOut() << std::endl;
    bool reciprocalEdgeFound = false;
    for (int edgeId = 0; edgeId < bl->sizeIn(); edgeId++)
    {
      const ghidra::FlowBlock* input_block = bl->getIn(edgeId);
      for (int remoteEdgeId = 0; remoteEdgeId < input_block->sizeOut(); remoteEdgeId++)
      {
        if (input_block->getOut(remoteEdgeId) == bl)
        {
          reciprocalEdgeFound = true;
          break;
        }
      }
      if (!reciprocalEdgeFound)
        ss << padding.str() <<  "\t\tReciprocal output edge missing from Block #" << input_block->getIndex() << std::endl;
    }
    reciprocalEdgeFound = false;
    for (int edgeId = 0; edgeId < bl->sizeOut(); edgeId++)
    {
      const ghidra::FlowBlock* output_block = bl->getOut(edgeId);
      for (int remoteEdgeId = 0; remoteEdgeId < output_block->sizeIn(); remoteEdgeId++)
      {
        if (output_block->getIn(remoteEdgeId) == bl)
        {
          reciprocalEdgeFound = true;
          break;
        }
      }
      if (!reciprocalEdgeFound)
        ss << padding.str() << "\t\tReciprocal input edge missing from Block #" << output_block->getIndex() << std::endl;
    }
    int i = 0;
    for (auto sub = bl->subBlock(i); sub != nullptr; i++)
    {
      auditBlockGraph(sub, ss, level + 1);
    }
  }
}
