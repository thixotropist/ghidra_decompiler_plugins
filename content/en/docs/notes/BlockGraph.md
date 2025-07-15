---
title: BlockGraph transforms
weight: 40
---

>Note: We want to understand how to edit BlockGraph objects to remove useless DoWhile blocks.

## possible exemplars

### ActionDoNothing

The Action `ActionDoNothing` defined in `coreaction.hh` claims to remove pointless blocks.
It is added to the `ActionGroup` `actfullloop` in `coreaction.cc` and selectively invokes `data.removeDoNothingBlock`.

### Funcdata::spliceBlockBasic

`funcdata_block.cc` includes a function to merge the current block with the following block,
if that current block has only a single output.

```c
void Funcdata::spliceBlockBasic(BlockBasic *bl)
```

* calls `PcodeOp::splice`, `BlockBasic::setOrder`, `BlockBasic::mergeRange`, `BlockBasic::mergeRange`,
   `BlockBasic::spliceBlock`, and `FuncData::structureReset`
* used by `ActionRedundBranch::apply`

 ### BlockDoWhile

* defined in `block.hh`, derived from class BlockGraph
* built with `newBlockDoWhile`
    * calling `identifyInternal`, `addBlock`, and `forceOutputNum`
* created in `blockaction.cc`
* associated with rule `ruleBlockDoWhile`

* BlockGraph::removeBlock looks relevant
    * used by `spliceBlock`, `Funcdata::blockRemoveInternal`, 