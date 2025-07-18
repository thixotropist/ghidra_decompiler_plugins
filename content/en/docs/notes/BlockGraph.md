---
title: BlockGraph transforms
weight: 40
---

>Summary: We want to understand how to edit BlockGraph objects to remove useless DoWhile blocks.

## Example: whisper_sample_1

Collect the output for `graph.printTree(ss, 1);` where the BlockGraph covers the function

```c
void string_constructor(void *this,char *param1,void *allocator)

{
  long lVar1;
  undefined8 uVar2;
  long lVar3;
  char *pcVar4;
  long lVar5;
  undefined auVar6 [256];
  long in_vl;
  
  lVar1 = (long)this + 0x10;
  *(long *)this = lVar1;
  if (param1 == (char *)0x0) {
    func_0x0001f950(0xfa298);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  lVar3 = 0;
  pcVar4 = param1;
  do {
    uVar2 = vsetvli_e8m1tama(0);
    pcVar4 = pcVar4 + lVar3;
    auVar6 = vle8ff_v(pcVar4);
    auVar6 = vmseq_vi(auVar6,0);
    lVar5 = vfirst_m(auVar6);
    lVar3 = in_vl;
  } while (lVar5 < 0);
  pcVar4 = pcVar4 + (lVar5 - (long)param1);
  if (pcVar4 < (char *)0x10) {
    if (pcVar4 == (char *)0x1) {
      *(char *)((long)this + 0x10) = *param1;
      goto code_r0x000209fe;
    }
    if (pcVar4 == (char *)0x0) goto code_r0x000209fe;
  }
  else {
    lVar1 = func_0x0001fad0(pcVar4 + 1,uVar2);
    *(long *)this = lVar1;
    *(char **)((long)this + 0x10) = pcVar4;
  }
  do {
    vector_memcpy((void *)lVar1,(void *)param1,(ulong)pcVar4);
  } while ;
code_r0x000209fe:
                    /* WARNING: Load size is inaccurate */
  *(char **)((long)this + 8) = pcVar4;
  pcVar4[*this] = '\0';
  return;
}

```

```text
  0
    List block 0
      If block 0
        List block 0
          If block 0
            Basic Block 0 0x000209be-0x000209cc
            Basic Block 1 0x00020a54-0x00020a60
          List block 2
            Basic Block 2 0x000209ce-0x000209d0
            Dowhile block 3
              Basic Block 3 0x000209d2-0x000209e8
            Basic Block 4 0x000209ec-0x000209f2
        Basic Block 5 0x00020a18-0x00020a3a
        List block 6
          If block 6
            Basic Block 6 0x000209f6-0x000209f8
            Plain goto block 7
              Basic Block 7 0x00020a10-0x00020a16
          If block 8
            Basic Block 8 0x000209fc-0x000209fc
      List block 9
        Dowhile block 9
          Basic Block 9 0x00020a3e-0x00020a50
        Basic Block 10 0x000209fe-0x00020a0e
```

The container relationship here is roughly:
* every `BlockGraph` contains a vector of `FlowBlock*` named `list`.
* the printTree method iterates over this vector,
  adding an indent level at each descent if the `FlowBlock` is itself a `BlockGraph`.
* PcodeOps are contained within `BasicBlocks`.

If we wanted to remove the Dowhile block we would need to edit the `list` of `List block 9`
to remove `Dowhile block 9` after promoting `Basic Block 9` in its place.

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