---
title: Do While Blocks
weight: 50
---

The code to insert a new Do While block into a blockgraph is

```c++
BlockDoWhile *BlockGraph::newBlockDoWhile(FlowBlock *condcl)
{
  vector<FlowBlock *> nodes;
  BlockDoWhile *ret = new BlockDoWhile();
  nodes.push_back(condcl);
  identifyInternal(ret,nodes);
  addBlock(ret);
  ret->forceOutputNum(1);
  return ret;
}
```

The function `BlockGraph::identifyInternal` does something complicated, editing the
given BlockGraph's `list` of FlowBlocks to include the new `BlockDoWhile`.

BlockGraph::newBlockDoWhile is called only by CollapseStructure::ruleBlockDoWhile
