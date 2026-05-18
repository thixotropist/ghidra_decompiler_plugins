---
title: BlockGraph transforms
weight: 40
description: Changing the default C-like control flow requires BlockGraph transforms
---

>Summary: For this example we want to understand how to edit BlockGraph objects to remove useless DoWhile blocks.
>         That can mean updating a lot of internal pointers.

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
* the `printTree` method iterates over this vector,
  adding an indent level at each descent if the list element `FlowBlock` is itself a `BlockGraph`.
  Not all links into `FlowBlock`  objects are present in these `list` objects - only container links,
  not goto links or If alternates.
* PcodeOps are contained within `BasicBlocks`, derived from `FlowBlock` but not from `BlockGraph`.
* The BlockGraph doesn't reference `BasicBlocks` directly, but indirectly through `BlockCopy` clones of
  `BasicBlocks`.
    * If a `BasicBlock` is copied to a `BlockCopy` its `copymap` member will point to the copied `BlockCopy`.

If we wanted to remove the `DoWhile` block we would need to edit the `list` of `List block 9`
to remove `DoWhile block 9` after promoting the `BlockCopy` of `Basic Block 9` in its place.

## possible exemplars

`BlockGraph` objects are generally not edited after creation, so we need to hunt for methods and constraints
relevant to our edit exercise.

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

* defined in `block.hh`, derived from class `BlockGraph`
* built with `newBlockDoWhile`
    * calling `identifyInternal`, `addBlock`, and `forceOutputNum`
* created in `blockaction.cc`
* associated with rule `ruleBlockDoWhile`

* `BlockGraph::removeBlock` looks relevant
    * used by `spliceBlock`, `Funcdata::blockRemoveInternal`

## Design considerations

We want to edit portions of a function's `BlockGraph`, specifically the `list` private member vector.
This implies adding new methods to existing classes like `FlowGraph` or `BlockGraph`.  It likely involves
invoking private or protected member functions within those classes.  We need to make any implementing code
match the design and consistency requirements of the existing Ghidra decompiler code, for example renumbering
blocks and verifying edge consistency.

>TODO: It's not clear whether edge consistency is required, as edges are used in generating the function's
>      BlockGraph tree and may not be used during the cleanup ActionGroup holding our plugin.

## Design iterations

>Warning: the methods added in this section have been replaced in later iterations.

Patch the released decompiler code to add two new methods to `BlockGraph`.
The first implementation is simply:

```c++
/// Replace a block in our list, resetting the parent
void BlockGraph::replaceBlock(FlowBlock* bl, int4 index)
{
  list[index]->parent = nullptr;
  bl->parent = this;
  list[index] = bl;
}

void BlockGraph::removeBlockReference(const FlowBlock* bl)
{
  auto it = std::find(list.begin(), list.end(), bl);

  if (it != list.end())
  {
    list.erase(it);
  }
}
```

`BlockGraph::replaceBlock` is needed to edit a `BlockList` object,
replacing a reference to the `BlockDoWhile` object with the `BlockCopy` linking to
what was the vector loop stanza.

`BlockGraph::removeBlockReference` is needed to edit the `BlockDoWhile` to remove the
link to that vector stanza `BlockCopy` so that we can delete the `BlockDoWhile` without affecting
the `BlockCopy`.

The plugin transform code then needs to move input and output edges terminating on the `BlockDoWhile`
to the `BlockCopy` objects.

>Note: There should be a more elegant single `BlockGraph` method to handle all of this, in which a child
>      node succeeds or replaces its parent node, inheriting all of the links owned by the deceased parent.

The implementing code now passes all but two integration tests, throwing a segfault when recursively descending
a `BlockGraph::markUnstructured` and trying to access a `list` member.  Thw `whisper_main` test is the first of the
two failing tests, with the last log entry referencing a strlen-like vector stanza.  The `markUnstructured` methods
apparently reference 'unstructured edges', suggesting the problem involves some subtle difference between edges.
Valgrind says that the segfault occurs when descending into a `BlockGoto` object, which we haven't seen before.

The next steps are:

* add additional diagnostics to display the state of `BlockGraph` objects.  This should be called on `BlockGraph` objects
  modified by the transform code.
* add additional log flush invocations
* explore whether were correct in adding a goto operation at the end of vector stanzas.

### debugging a segfault

Two of the integration tests now throw segfaults.  Select one of them, and run the data test under gdb

```console
$ SLEIGHHOME=/opt/ghidra_12.0_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so gdb /opt/ghidra_12.0_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest
...
(gdb) run < test/whisper_main.ghidra
Starting program: /opt/ghidra_12.0_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_main.ghidra
...
[decomp]> decompile main
Decompiling main

Program received signal SIGSEGV, Segmentation fault.
0x0000000801000004 in ?? ()
(gdb) bt
#0  0x0000000801000004 in ?? ()
#1  0x0000000000a019e2 in ghidra::FlowBlock::getFrontLeaf (this=0x2df8b60)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc:358
#2  0x0000000000a0a143 in ghidra::BlockGoto::gotoPrints (this=0x2e12cd0)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc:2858
#3  0x0000000000a0a03b in ghidra::BlockGoto::markUnstructured (this=0x2e12cd0)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc:2833
#4  0x0000000000a04a9a in ghidra::BlockGraph::markUnstructured (this=0x2a62a90)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc:1244
#5  0x0000000000a0ab24 in ghidra::BlockIf::markUnstructured (this=0x2a62a90)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc:3042
#6  0x0000000000a04a9a in ghidra::BlockGraph::markUnstructured (this=0x235df50)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc:1244
#7  0x0000000000a04a9a in ghidra::BlockGraph::markUnstructured (this=0x2698840)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc:1244
...
#28 0x0000000000a04a9a in ghidra::BlockGraph::markUnstructured (this=0x29caf90)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc:1244
#29 0x0000000000a04a9a in ghidra::BlockGraph::markUnstructured (this=0xf367a8)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc:1244
#30 0x0000000000a2243c in ghidra::ActionFinalStructure::apply (this=0xfe9d80, data=...)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/blockaction.cc:2202
#31 0x00000000009e0aed in ghidra::Action::perform (this=0xfe9d80, data=...)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/action.cc:319
#32 0x00000000009e1678 in ghidra::ActionGroup::apply (this=0xfe02b0, data=...)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/action.cc:514
#33 0x00000000009e1928 in ghidra::ActionRestartGroup::apply (this=0xfe02b0, data=...)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/action.cc:560
#34 0x00000000009e0aed in ghidra::Action::perform (this=0xfe02b0, data=...)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/action.cc:319
--Type <RET> for more, q to quit, c to continue without paging--
#35 0x00000000008d3875 in ghidra::IfcDecompile::execute (this=0xeff890, s=...)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ifacedecomp.cc:908
#36 0x00000000008feec1 in ghidra::IfaceStatus::runCommand (this=0xf01980)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/interface.cc:369
#37 0x00000000008e640d in ghidra::execute (status=0xf01980, dcp=0xef5450)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ifacedecomp.cc:3620
#38 0x00000000008e6869 in ghidra::mainloop (status=0xf01980)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ifacedecomp.cc:3661
#39 0x00000000008c13ed in main (argc=1, argv=0x7fffffffdc08)
    at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/consolemain.cc:234
```

The segfault occurs at `block.cc:358`

```c
FlowBlock *FlowBlock::getFrontLeaf(void)

{
  FlowBlock *bl = this;
  while(bl->getType() != t_copy) {
    bl = bl->subBlock(0);
    if (bl == (FlowBlock *)0) return bl;
  }
  return bl;
}
```

The backtrace shows that the segfault occurs outside of our plugin, during the `graph.markUnstructured` invocation of `ActionFinalStructure`

```c++
int4 ActionFinalStructure::apply(Funcdata &data)

{
  BlockGraph &graph(data.getStructure());

  graph.orderBlocks();
  graph.finalizePrinting(data);
  graph.scopeBreak(-1,-1);	// Put in \e break statements
  graph.markUnstructured();	// Put in \e gotos
  graph.markLabelBumpUp(false); // Fix up labeling
  return 0;
}
```

The backtrace suggests that a `BlockGoto` has a corrupted `getGotoTarget()`.

Narrow the scope some by trying different values for `TRANSFORM_LIMIT`.  With 7 transforms allowed the decompilation completes with no errors.

```text
[2025-08-08 15:53:58.260] [riscv_vector] [trace] Examining full function BlockGraph Tree form after transform:
  0
    List block 0
      If block 0
        Condition block(||) 0
          Basic Block 0 0x00020fd0-0x000211f4
          Basic Block 1 0x000211fa-0x000211fa
        Basic Block 2 0x00022fce-0x00022fe6
        If block 3
          Basic Block 3 0x00021202-0x00021218
          Basic Block 4 0x00021938-0x00021946
          List block 5
            If block 5
              Basic Block 5 0x0002121c-0x00021222
              List block 6
                If block 6
                  List block 6
                    If block 6
                      Basic Block 6 0x00021226-0x00023654
                      List block 7
                        Basic Block 7 0x00023862-0x00023862
                        Dowhile block 8
                          Basic Block 8 0x00023866-0x00023878
                      Basic Block 9 0x00023658-0x00023668
                    Basic Block 10 0x0002366a-0x000236b8
                  Plain goto block 12
                    Basic Block 12 0x0002389c-0x000238a4
                Plain goto block 11
                  Basic Block 11 0x000236bc-0x00023706
            Basic Block 13 0x0002122a-0x00021240
      Infinite loop block 14
        List block 14
          If block 14
            Basic Block 14 0x00021244-0x00021278
            List block 15
              If block 15
                List block 15
                  Dowhile block 15
                    List block 15
                      Whiledo block 15
                        Basic Block 15 0x00021280-0x0002128c
                        If block 23
                          Basic Block 23 0x00021294-0x00021294
                      List block 16
                        If block 16
                          Basic Block 16 0x0002191e-0x00021928
                        List block 17
                          If block 17
                            List block 17
                              Basic Block 17 0x0002192a-0x00022c9c
                              Whiledo block 18
                                Basic Block 18 0x00022c9c-0x00022c9c
                                Basic Block 19 0x00022ca0-0x00022cae
                              Basic Block 20 0x00022cb2-0x00022cc6
                            Basic Block 21 0x00022cca-0x00022cd0
                          Basic Block 22 0x00022cd4-0x00022cd8
                  Basic Block 24 0x00021298-0x0002129c
              If block 25
                List block 25
                  If block 25
                    List block 25
                      If block 25
                        Condition block(&&) 25
                          Basic Block 25 0x000212a4-0x000212c2
                          Basic Block 26 0x000212c4-0x00023012
                        List block 27
                          Basic Block 27 0x0002301a-0x00023030
                          Plain goto block 31
                            Basic Block 31 0x00023034-0x00023050
                      Condition block(&&) 28
                        Basic Block 28 0x000212c8-0x000212cc
                        Basic Block 29 0x000212ce-0x000212d2
                    Plain goto block 30
                      Basic Block 30 0x000212d4-0x0002332a
                  List block 32
                    If block 32
                      Basic Block 32 0x000212d8-0x000212dc
                      Basic Block 33 0x000212de-0x000212e8
                    Basic Block 34 0x000212ec-0x0002130e
                List block 58
                  If block 58
                    List block 58
                      Basic Block 58 0x00021442-0x00021450
                      Basic Block 59 0x00021454-0x00021466
                      Basic Block 60 0x00021468-0x0002146e
                    Plain goto block 61
                      Basic Block 61 0x00021470-0x000237f2
                  If block 62
                    Basic Block 62 0x00021474-0x00021484
                    List block 84
                      If block 84
                        Basic Block 84 0x0002148a-0x000214c2
                        Plain goto block 85
                          List block 85
                            If block 85
                              List block 85
                                If block 85
                                  List block 85
                                    If block 85
                                      Basic Block 85 0x000214c6-0x000214f0
                                      Plain goto block 86
                                        Basic Block 86 0x00021f60-0x00021f6c
                                    List block 87
                                      If block 87
                                        Basic Block 87 0x000214f4-0x000214f6
                                        Basic Block 88 0x00021f8e-0x00021f96
                                        Whiledo block 89
                                          Basic Block 89 0x000214fa-0x000214fa
                                          Basic Block 90 0x00021f72-0x00021f84
                                      Basic Block 91 0x0002150a-0x00021522
                                  List block 93
                                    If block 93
                                      Basic Block 93 0x00021a2a-0x00021a4c
                                      Plain goto block 97
                                        Basic Block 97 0x00021f9a-0x00021faa
                                    List block 94
                                      If block 94
                                        Basic Block 94 0x00021a50-0x00021a52
                                        Basic Block 99 0x00021948-0x0002194e
                                        If block 95
                                          Basic Block 95 0x00021a56-0x00021a56
                                      Basic Block 100 0x00021952-0x0002195c
                                  List block 92
                                    List block 92
                                      If block 92
                                        List block 92
                                          If block 92
                                            Basic Block 92 0x00021526-0x0002152a
                                          Basic Block 96 0x0002152e-0x00021546
                                      If block 98
                                        Basic Block 98 0x0002154a-0x0002154c
                                    Dowhile block 101
                                      Basic Block 101 0x00021552-0x00021564
                                Basic Block 102 0x0002156a-0x000215ae
                              Plain goto block 103
                                If block 103
                                  List block 103
                                    If block 103
                                      List block 103
                                        If block 103
                                          Condition block(&&) 103
                                            Basic Block 103 0x000215b2-0x000215b8
                                            Condition block(||) 104
                                              Basic Block 104 0x000215ba-0x000215d8
                                              Basic Block 105 0x000215da-0x000215de
                                          Basic Block 106 0x000215e0-0x00021616
                                        If block 107
                                          Basic Block 107 0x0002161a-0x0002161e
                                          Basic Block 108 0x00021fec-0x00022004
                                        If block 109
                                          Basic Block 109 0x00021622-0x00021626
                                          List block 110
                                                If block 110
                                                  Basic Block 110 0x0002162a-0x000216ba
                                                  Basic Block 111 0x000216bc-0x000216c0
                                                Basic Block 112 0x000216c4-0x000216d0
                                              Basic Block 113 0x000216d4-0x000216d8
                                            Basic Block 114 0x000216dc-0x0002170a
                                        List block 115
                                          If block 115
                                            Condition block(||) 115
                                              Basic Block 115 0x0002170e-0x0002173c
                                              Basic Block 116 0x00021740-0x00021746
                                            Basic Block 117 0x00021748-0x0002174e
                                          If block 118
                                            Basic Block 118 0x00021750-0x0002179c
                                            Basic Block 119 0x000217a0-0x000217a8
                                          Basic Block 120 0x000217aa-0x000217c6
                                      If block 121
                                        Condition block(||) 121
                                          Basic Block 121 0x00021fae-0x00021fb2
                                          Basic Block 122 0x00021fb4-0x00021fb4
                                        Basic Block 123 0x00021fbc-0x00021fc6
                                        Basic Block 124 0x00021fb8-0x000230b6
                                      If block 125
                                        Basic Block 125 0x000217ca-0x000217d4
                                        Basic Block 126 0x000217d6-0x000217d6
                                    List block 127
                                      If block 127
                                        Basic Block 127 0x000217da-0x00021804
                                        Basic Block 128 0x00021806-0x00021806
                                      List block 129
                                        If block 129
                                          Basic Block 129 0x0002180a-0x0002182a
                                          Basic Block 130 0x0002182c-0x0002182c
                                        Basic Block 131 0x00021830-0x0002189a
                                  Plain goto block 132
                                    If block 132
                                      Basic Block 132 0x0002189e-0x000218a6
                                      List block 133
                                        Basic Block 133 0x000218ae-0x000218e2
                                        Infinite loop block 134
                                          List block 134
                                            If block 134
                                              List block 134
                                                If block 134
                                                  Condition block(||) 134
                                                    Basic Block 134 0x000218e4-0x000218e8
                                                    Basic Block 135 0x000218ea-0x000218f0
                                                  List block 136
                                                    List block 136
                                                      If block 136
                                                        Basic Block 136 0x000218f2-0x000218f6
                                                      If block 137
                                                        Basic Block 137 0x000218fa-0x000218fe
                                                        Plain goto block 138
                                                          Basic Block 138 0x00021902-0x00021902
                                                    Basic Block 141 0x0002195e-0x00021962
                                                  List block 139
                                                    If block 139
                                                      Basic Block 139 0x00021906-0x00021906
                                                    Basic Block 140 0x0002190a-0x00021910
                                                Basic Block 142 0x00021962-0x00021962
                                            Basic Block 178 0x00021914-0x0002191c
                            Basic Block 334 0x00021fca-0x00021fe4
                      List block 342
                        If block 342
                          Basic Block 342 0x00021f48-0x00021f4c
                          Basic Block 343 0x00021f4e-0x00021f50
                        Basic Block 344 0x00021f54-0x00021f5c
                    List block 63
                      If block 63
                        List block 63
                          If block 63
                            Basic Block 63 0x00021486-0x00023196
                            List block 64
                              If block 64
                                Basic Block 64 0x00023546-0x0002357e
                                Basic Block 65 0x00023580-0x000235b6
                              Basic Block 66 0x000235ba-0x00023610
                            List block 67
                              If block 67
                                Basic Block 67 0x0002319a-0x000231e2
                                Whiledo block (overflow) 68
                                  List block 68
                                    If block 68
                                      Condition block(&&) 68
                                        Basic Block 68 0x00023812-0x0002381a
                                        Basic Block 69 0x00023852-0x0002385c
                                    Basic Block 70 0x0002381e-0x0002381e
                                  If block 71
                                    Basic Block 71 0x00023822-0x00023844
                                    Basic Block 72 0x0002387c-0x00023884
                                    Basic Block 73 0x00023848-0x00023850
                                Basic Block 74 0x000231e6-0x000231e6
                              List block 75
                                Basic Block 75 0x000231e8-0x00023200
                                Whiledo block (overflow) 76
                                  Basic Block 76 0x00023202-0x00023234
                                  List block 346
                                    If block 346
                                      Basic Block 346 0x00023238-0x00023240
                                      List block 347
                                        If block 347
                                          Basic Block 347 0x00023276-0x0002328a
                                          Basic Block 348 0x00023612-0x00023618
                                          Whiledo block 349
                                            Basic Block 349 0x0002328e-0x0002328e
                                            Basic Block 350 0x00023298-0x000232aa
                                        If block 351
                                          Basic Block 351 0x000232ac-0x000232b6
                                          Basic Block 352 0x000232ba-0x000232c0
                                        Basic Block 353 0x000232c4-0x000232d0
                                    If block 354
                                      Basic Block 354 0x00023244-0x00023268
                                      Basic Block 355 0x000237cc-0x000237d4
                                      Basic Block 356 0x0002326c-0x00023274
                                List block 77
                                  If block 77
                                    Basic Block 77 0x000233fa-0x00023444
                                    Basic Block 78 0x00023446-0x0002347c
                                  If block 79
                                    Basic Block 79 0x00023480-0x000234ec
                                    Basic Block 80 0x000234f0-0x000234f6
                                  Basic Block 81 0x000234fa-0x000234fc
                          Basic Block 82 0x00023500-0x00023514
                        Plain goto block 83
                          Basic Block 83 0x00023518-0x00023542
                      Basic Block 345 0x00023886-0x00023898
                List block 35
                  List block 35
                    If block 35
                      List block 35
                        If block 35
                          List block 35
                            If block 35
                              Basic Block 35 0x00021312-0x0002132e
                              Basic Block 36 0x00021330-0x00021344
                            Basic Block 37 0x00021348-0x0002135c
                          Basic Block 38 0x0002135e-0x0002135e
                        If block 39
                          List block 39
                            If block 39
                              Basic Block 39 0x00021360-0x00021374
                              Basic Block 40 0x00021376-0x00021376
                            If block 41
                              Basic Block 41 0x00021378-0x0002138c
                              Basic Block 42 0x0002138e-0x0002138e
                            If block 43
                              Basic Block 43 0x00021390-0x000213a4
                              Basic Block 44 0x000213a6-0x000213a6
                            Basic Block 45 0x000213a8-0x000213bc
                          Basic Block 46 0x000213be-0x000213be
                        If block 47
                          List block 47
                            If block 47
                              List block 47
                                If block 47
                                  Basic Block 47 0x000213c0-0x000213d4
                                  Basic Block 48 0x000213d6-0x000213d6
                                Basic Block 49 0x000213d8-0x000213ec
                              Basic Block 50 0x000213ee-0x000213ee
                            If block 51
                              Basic Block 51 0x000213f0-0x00021404
                              Basic Block 52 0x00021406-0x00021406
                            Basic Block 53 0x00021408-0x0002141c
                          Basic Block 54 0x0002141e-0x0002141e
                        Basic Block 55 0x00021420-0x00021434
                      Plain goto block 56
                        Basic Block 56 0x00021436-0x0002305c
                    List block 57
                      If block 57
                        Basic Block 57 0x0002143a-0x0002143a
                      Basic Block 357 0x0002143e-0x000230fc
                  Basic Block 358 0x00023100-0x00023100
            Basic Block 359 0x000233c0-0x000233f8
          List block 360
            List block 360
              Whiledo block (overflow) 360
                List block 360
                  If block 360
                    Basic Block 360 0x00023102-0x0002315a
                    Basic Block 361 0x0002315e-0x00023188
                  Basic Block 362 0x0002390e-0x0002392a
                Basic Block 380 0x000238a6-0x000238ca
              Basic Block 363 0x0002392c-0x00023936
            List block 364
              If block 364
                List block 364
                  If block 364
                    Basic Block 364 0x0002393a-0x0002393a
                    Basic Block 365 0x0002393e-0x00023944
                  Basic Block 366 0x00023948-0x00023962
                Basic Block 367 0x00023964-0x0002396a
              If block 368
                Basic Block 368 0x0002396e-0x0002397c
                Basic Block 369 0x00023980-0x00023986
              If block 370
                Basic Block 370 0x0002398a-0x00023998
                Basic Block 371 0x0002399c-0x000239a6
              Whiledo block 372
                Basic Block 372 0x0002372e-0x00023732
                List block 373
                  Basic Block 373 0x00023708-0x0002371a
                  Basic Block 374 0x0002371e-0x0002372c
              List block 375
                If block 375
                  List block 375
                    If block 375
                      Basic Block 375 0x00023734-0x00023774
                      Dowhile block 376
                        Basic Block 376 0x0002378e-0x000237a2
                    Basic Block 377 0x000237a6-0x000237b4
                  Basic Block 378 0x000237b8-0x000237be
                Basic Block 379 0x000237c2-0x000237c8
    Plain goto block 143
      List block 143
        If block 143
          Basic Block 143 0x00021966-0x00021980
          List block 144
            If block 144
              Condition block(||) 144
                Basic Block 144 0x00021988-0x00021990
                Basic Block 145 0x00021992-0x000219a6
              List block 146
                If block 146
                  List block 146
                    If block 146
                      Basic Block 146 0x000219a8-0x000219b4
                    Basic Block 147 0x000219b8-0x000219b8
                Basic Block 148 0x000219c0-0x000219c0
            If block 149
              Basic Block 149 0x000219c2-0x000219c2
              List block 150
                Basic Block 150 0x000219ca-0x000219f2
                Infinite loop block 151
                  List block 151
                    If block 151
                      List block 151
                        If block 151
                          Condition block(||) 151
                            Basic Block 151 0x000219f4-0x000219f8
                            Basic Block 152 0x000219fa-0x00021a00
                          List block 153
                            List block 153
                              If block 153
                                Basic Block 153 0x00021a02-0x00021a06
                              If block 154
                                Basic Block 154 0x00021a0a-0x00021a0a
                                Plain goto block 155
                                  Basic Block 155 0x00021a0e-0x00021a0e
                            Basic Block 158 0x00021fe6-0x00021fea
                          List block 156
                            If block 156
                              Basic Block 156 0x00021a12-0x00021a12
                            Basic Block 157 0x00021a16-0x00021a18
                        Basic Block 159 0x00021a1c-0x00021a1c
                    Basic Block 177 0x00021a20-0x00021a28
        Basic Block 179 0x000232e4-0x00023304
    List block 160
      If block 160
        List block 160
          If block 160
            List block 160
              List block 160
                If block 160
                  List block 160
                    If block 160
                      Basic Block 160 0x00021a66-0x00021a70
                    Condition block(||) 161
                      Basic Block 161 0x00021a78-0x00021a80
                      Basic Block 162 0x00021a82-0x00021a8c
                  If block 163
                    Basic Block 163 0x00021a8e-0x00021a9a
                    Plain goto block 164
                      List block 164
                        If block 164
                          Basic Block 164 0x00021a9e-0x00021a9e
                        Basic Block 165 0x00021aa6-0x00021aa6
                  If block 166
                    Basic Block 166 0x00021aa8-0x00021aa8
                    Plain goto block 167
                      List block 167
                        If block 167
                          List block 167
                            If block 167
                              Basic Block 167 0x00023c20-0x00023c32
                            If block 168
                              Basic Block 168 0x00023b3e-0x00023c44
                              Basic Block 169 0x00023b4a-0x00023b50
                            If block 170
                              Basic Block 170 0x00023b54-0x00023b6e
                              Basic Block 171 0x00023b70-0x00023b76
                            Basic Block 172 0x00023b7a-0x00023b88
                          Basic Block 173 0x00023b8c-0x00023b92
                        If block 174
                          Basic Block 174 0x00023b96-0x00023ba4
                          Basic Block 175 0x00023ba8-0x00023bb2
                Basic Block 176 0x00021ab0-0x00021abc
              List block 180
                If block 180
                  List block 180
                    If block 180
                      Basic Block 180 0x00021ac0-0x00021ade
                      Basic Block 181 0x00021ae0-0x00021aec
                    Basic Block 182 0x00021af0-0x00021b60
                    Dowhile block 183
                      Basic Block 183 0x00021b64-0x00021b76
                    Basic Block 184 0x00021b78-0x00021b7e
                  Plain goto block 185
                    List block 185
                      If block 185
                        Basic Block 185 0x00021b80-0x00023352
                        Basic Block 186 0x00023354-0x0002335a
                      If block 187
                        Basic Block 187 0x0002335e-0x00023378
                        Basic Block 188 0x0002337a-0x00023380
                      If block 189
                        Basic Block 189 0x00023384-0x00023392
                        Basic Block 190 0x00023396-0x0002339c
                      If block 191
                        Basic Block 191 0x000233a0-0x000233ae
                        Basic Block 192 0x000233b2-0x000233b8
                      Basic Block 193 0x000233bc-0x000233be
                List block 194
                  If block 194
                    List block 194
                      If block 194
                        List block 194
                          If block 194
                            List block 194
                              If block 194
                                Basic Block 194 0x00021b84-0x00021b88
                                Basic Block 195 0x00021b8a-0x00021b90
                              Basic Block 196 0x00021b94-0x00021b9e
                            List block 197
                              If block 197
                                Basic Block 197 0x000227b2-0x00022810
                                Basic Block 198 0x00023060-0x00023076
                                If block 199
                                  Basic Block 199 0x00022814-0x00022832
                                  List block 200
                                    Basic Block 200 0x00022836-0x00022840
                                    Dowhile block 201
                                      List block 201
                                        If block 201
                                          Condition block(&&) 201
                                            Basic Block 201 0x00022844-0x00022860
                                            Basic Block 202 0x00022862-0x0002286c
                                          List block 203
                                            If block 203
                                              Basic Block 203 0x00022f16-0x00022fa6
                                              Basic Block 204 0x00022faa-0x00022fb0
                                            Basic Block 205 0x00022fb4-0x00022fca
                                        If block 206
                                          Basic Block 206 0x00022870-0x00022896
                                          Basic Block 207 0x0002289a-0x000228a0
                                        Basic Block 208 0x000228a4-0x000228a6
                              If block 209
                                Basic Block 209 0x000228aa-0x0002291c
                                Basic Block 210 0x00022920-0x0002292a
                          List block 211
                            If block 211
                              Basic Block 211 0x00021ba2-0x00021ba6
                              If block 212
                                Basic Block 212 0x00022738-0x000227a0
                                Basic Block 213 0x000227a4-0x000227ae
                            Basic Block 214 0x00021baa-0x00021bae
                        List block 215
                          If block 215
                            Basic Block 215 0x000224a6-0x00022510
                            Basic Block 216 0x0002307a-0x00023090
                            If block 217
                              Basic Block 217 0x00022514-0x00022532
                              List block 218
                                Basic Block 218 0x00022536-0x00022556
                                Dowhile block 219
                                  List block 219
                                    If block 219
                                      Condition block(&&) 219
                                        Basic Block 219 0x00022558-0x00022590
                                        Basic Block 220 0x00022592-0x000225a0
                                      List block 221
                                        If block 221
                                          Basic Block 221 0x00022e82-0x00022ee0
                                          Basic Block 222 0x00022ee4-0x00022eea
                                        Basic Block 223 0x00022eee-0x00022f04
                                    List block 224
                                      If block 224
                                        Basic Block 224 0x000225a4-0x00022620
                                        Basic Block 225 0x00022624-0x0002262a
                                      If block 226
                                        Basic Block 226 0x0002262e-0x00022636
                                        Basic Block 227 0x0002263a-0x00022640
                                      If block 228
                                        Basic Block 228 0x00022644-0x0002266e
                                        Basic Block 229 0x00022672-0x00022678
                                      Basic Block 230 0x0002267c-0x0002267c
                          If block 231
                            Basic Block 231 0x00022680-0x00022726
                            Basic Block 232 0x0002272a-0x00022734
                      List block 233
                        If block 233
                          Basic Block 233 0x00021bb2-0x00021bb6
                          If block 234
                            Basic Block 234 0x000223f6-0x00022494
                            Basic Block 235 0x00022498-0x000224a2
                        Basic Block 236 0x00021bba-0x00021bbe
                    List block 237
                      If block 237
                        Basic Block 237 0x00022084-0x00022112
                        Basic Block 238 0x00022114-0x000230aa
                        If block 239
                          List block 239
                            If block 239
                              Condition block(&&) 239
                                Basic Block 239 0x00022118-0x00022150
                                Basic Block 240 0x00022152-0x0002216a
                              Basic Block 241 0x0002216e-0x00023802
                            Basic Block 242 0x00022172-0x0002218a
                          List block 243
                            Basic Block 243 0x0002218e-0x000221ca
                            Dowhile block 244
                              List block 244
                                If block 244
                                  Basic Block 244 0x000221cc-0x000221ee
                                  Basic Block 258 0x00023054-0x00023056
                                  If block 245
                                    List block 245
                                      Dowhile block 245
                                        Basic Block 245 0x000221f6-0x0002220c
                                      Basic Block 246 0x00022210-0x0002221c
                                    List block 247
                                      If block 247
                                        List block 247
                                          Basic Block 247 0x00022220-0x00022226
                                          Dowhile block 248
                                            Basic Block 248 0x00022228-0x00022238
                                          Basic Block 249 0x0002223a-0x0002224c
                                      List block 250
                                        Basic Block 250 0x00022250-0x0002225a
                                        Whiledo block (overflow) 251
                                          List block 251
                                            Basic Block 251 0x0002225c-0x00022266
                                            Whiledo block 252
                                              Basic Block 252 0x00022266-0x00022266
                                              List block 253
                                                If block 253
                                                  Basic Block 253 0x0002226a-0x0002226e
                                                Basic Block 254 0x00022272-0x0002227e
                                            Basic Block 255 0x00022282-0x0002228a
                                          Basic Block 256 0x0002228e-0x00022290
                                    If block 257
                                      Basic Block 257 0x00022292-0x0002229a
                                List block 259
                                  If block 259
                                    Condition block(&&) 259
                                      Basic Block 259 0x0002229e-0x000222d8
                                      Basic Block 260 0x000222da-0x000222e8
                                    List block 261
                                      If block 261
                                        Basic Block 261 0x00022d2a-0x00022da2
                                        Basic Block 262 0x00022da6-0x00022dac
                                      Basic Block 263 0x00022db0-0x00022dc6
                                  Basic Block 264 0x000222ec-0x0002231e
                      If block 265
                        Basic Block 265 0x00022322-0x000223e4
                        Basic Block 266 0x000223e8-0x000223f2
                  List block 267
                    If block 267
                      List block 267
                        If block 267
                          Basic Block 267 0x00021bc2-0x00021bc6
                          If block 268
                            Basic Block 268 0x00022008-0x00022074
                            Basic Block 269 0x00022078-0x00022082
                        Basic Block 270 0x00021bca-0x00021bce
                      List block 271
                        If block 271
                          Basic Block 271 0x0002292e-0x00022998
                          Basic Block 272 0x00022baa-0x00022bbc
                          If block 273
                            Basic Block 273 0x0002299c-0x000229c8
                            List block 274
                              Basic Block 274 0x000229cc-0x00022a30
                              Dowhile block 275
                                List block 275
                                      If block 275
                                        Condition block(&&) 275
                                          Basic Block 275 0x00022ac2-0x00022b6e
                                          Basic Block 276 0x00022b70-0x00022b7c
                                        List block 277
                                          If block 277
                                            Basic Block 277 0x00022dca-0x00022e5c
                                            Basic Block 278 0x00022e60-0x00022e66
                                          Basic Block 279 0x00022e6a-0x00022e80
                                      If block 280
                                        Basic Block 280 0x00022b80-0x00022b96
                                        Basic Block 281 0x00022a32-0x00022a3a
                                        Basic Block 282 0x00022b9a-0x00022ba2
                                      If block 283
                                        Basic Block 283 0x00022a3e-0x00022a5e
                                        Basic Block 284 0x00022ba4-0x00022ba8
                                        Basic Block 285 0x00022a62-0x00022a6c
                                      If block 286
                                        Basic Block 286 0x00022a6e-0x00022a98
                                        Basic Block 287 0x00022a9c-0x00022aa2
                                      Basic Block 288 0x00022aa6-0x00022aae
                                    Basic Block 289 0x00022ab2-0x00022ab8
                                  Basic Block 290 0x00022abc-0x00022abe
                        If block 291
                          Basic Block 291 0x00022bc0-0x00022c66
                          Basic Block 292 0x00022c6e-0x00022c78
                    Basic Block 293 0x00021bd2-0x00021bd6
          Basic Block 294 0x00021bda-0x00021c04
        If block 295
          Basic Block 295 0x00021c0c-0x00021c0c
          List block 296
            If block 296
              Basic Block 296 0x00021c0e-0x000232d4
            Basic Block 297 0x000232d8-0x000232e0
        If block 298
          List block 298
            If block 298
              Basic Block 298 0x00021c08-0x00022cea
              List block 299
                If block 299
                  Basic Block 299 0x00022cee-0x00023c08
                Basic Block 300 0x00023c0c-0x00023c18
            List block 301
              If block 301
                Basic Block 301 0x00022cf2-0x00022cf8
                Basic Block 302 0x000230e0-0x000230e4
              Basic Block 303 0x00022cfc-0x00022d0c
          Dowhile block 304
            Basic Block 304 0x000230c8-0x000230da
          Basic Block 305 0x00022d10-0x00022d26
      List block 306
        List block 306
          If block 306
            List block 306
              If block 306
                Basic Block 306 0x00021c12-0x00021c2c
                List block 307
                  If block 307
                    Basic Block 307 0x00021c30-0x00023e62
                  Basic Block 308 0x00023e66-0x00023e72
              List block 309
                If block 309
                  Basic Block 309 0x00021c34-0x00021c42
                  Basic Block 310 0x00021c46-0x0002330a
                If block 311
                  Basic Block 311 0x00021c4e-0x00021c52
                  Basic Block 312 0x00021c5a-0x00021c6c
                  Basic Block 313 0x00021c56-0x00023004
                Basic Block 314 0x00021c70-0x00021ce6
            Dowhile block 315
              List block 315
                If block 315
                  Basic Block 315 0x00021cea-0x00021cf6
                  Dowhile block 316
                    List block 316
                      If block 316
                        List block 316
                          If block 316
                            Basic Block 316 0x00021d54-0x00021d7a
                            Basic Block 317 0x00021de0-0x00021df4
                            List block 318
                              Dowhile block 318
                                Basic Block 318 0x00021d7e-0x00021d94
                              Basic Block 319 0x00021d98-0x00021da2
                          List block 320
                            If block 320
                              Basic Block 320 0x00021da6-0x00021db8
                              Basic Block 321 0x00021cfc-0x00021d02
                              Basic Block 322 0x00021dba-0x00021dc4
                            Basic Block 323 0x00021d06-0x00021d32
                        List block 324
                          If block 324
                            Basic Block 324 0x00021d36-0x00023d86
                          Basic Block 325 0x00023d8a-0x00023d8e
                      List block 326
                        If block 326
                          Basic Block 326 0x00021d3a-0x00021d3e
                          If block 327
                            Basic Block 327 0x00021dc6-0x00021dd4
                            Basic Block 328 0x00021dd8-0x00021dde
                          Basic Block 329 0x00021d40-0x00021d40
                        Basic Block 330 0x00021d44-0x00021d50
                Basic Block 331 0x00021df6-0x00021e02
          If block 332
            Basic Block 332 0x00021e06-0x00021ea6
            Basic Block 333 0x00021eaa-0x00021eb0
        Plain goto block 335
          If block 335
            List block 335
              If block 335
                List block 335
                  If block 335
                    Basic Block 335 0x00021eb4-0x00021ece
                    Basic Block 336 0x00021ed0-0x00021ed6
                  Basic Block 337 0x00021eda-0x00021ee8
                Basic Block 338 0x00021eec-0x00021ef2
              If block 339
                Basic Block 339 0x00021ef6-0x00021f04
                Basic Block 340 0x00021f08-0x00021f0e
              Basic Block 341 0x00021f12-0x00021f44
```

The immediate cause of the segfault appears to be a descent of the function's BlockGraph leading
to an invalid block. This occurs well after our plugin finishes work, during a final cleanup
phase where the decompiler is inserting any explicit goto instructions not already covered by
C structured control blocks.  Apparently unstructured goto branches may not count as edges,
so we may be missing some link cleanup when deleting a `DoWhile` block.

Let's examine the main function in a vanilla Ghidra, identifying the structures that *should*
result in valid transforms.

There are 21 `vset*` instructions, of which 12 are `vsetivli` instructions. Seven of the `vsetvli`
instructions take the number of elements from a register, and may be eligible for transformation.

| Address | Notes |
|---------|-------|
| 0x21454 | vector_memcpy in DoWhile block, transformed |
| 0x21552 | vector_memcpy in DoWhile block, transformed  |
| 0x21b64 | vector_memcpy in DoWhile block, not transformed |
| 0x21f72 | vector_memcpy in While block, not transformed |
| 0x230c8 | vector_memcpy in DoWhile block, not transformed, with goto |
| 0x23298 | vector_memcpy in While block, not transformed |
| 0x23866 | vector_memcpy in DoWhile block, not transformed |

The results suggest a problem involving the BlockBasic ⇔ BlockCopy relationship, possibly edgeless goto blocks, block parents, or possibly block indexing.  We may still have some 'free' Varnodes in
transform blocks, which would be a problem.  And there is some evidence that problems occur during a
*second* pass through the function.

The main function is rather large, so let's switch to the smaller `whisper_sample_5` test case, as that fails in a similar fashion.  Additionally, disable the `printTree` invocation over the entire function
to minimize log file clutter.

#### whisper_wrap_segment inspection

Inspect `whisper_wrap_segment` in Ghidra with vector plugins enabled but with `DoWhile` block removal disabled.

* 24 `vector_memcpy` transforms completed
    * 16 loop transforms
        * 2 of these have a size varnode like `register0x00002050`
    * 8 non-loop transforms
* 1 `vector_strlen` stanza present but not recognized
* 1 vsetivli instruction located outside of the matching vector load and store instructions
* 1 possible `vector_memcpy` transforms not taken at 0xb9d50 - a nested do loop?

The log file shows some issues:

```console
$ grep warn ghidraRiscvLogger.log
[2025-08-17 10:24:48.265] [riscv_vector] [warning]     Unexpected op found in analysis: 13
[2025-08-17 10:24:48.278] [riscv_vector] [warning] Unable to safely remove register dependencies at 0xb9d50:4fb
[2025-08-17 10:24:48.291] [riscv_vector] [warning] Found possible orphan vset op at 0xba0a8
[2025-08-17 10:25:59.219] [riscv_vector] [warning]     Unexpected op found in analysis: 13
[2025-08-17 10:25:59.223] [riscv_vector] [warning] Unable to safely remove register dependencies at 0xb9d50:4fb
$ grep free ghidraRiscvLogger.log|grep -v goto
		syscall[#0x11000001:4](s0xffffffffffffff10(0x000b9de0:1871),s6(0x000b9dfe:574),a0(free))
0x000ba4e8:20e1:	vector_memcpy(s0xffffffffffffff10(0x000b9de0:1871),s6(0x000b9dfe:574),a0(free))
0x000ba4e8:20e1:	vector_memcpy(s0xffffffffffffff10(0x000b9de0:1871),s6(0x000b9dfe:574),a0(free))
		syscall[#0x11000001:4](s0xffffffffffffff10(0x000b9de0:1871),s6(0x000b9dfe:574),a2(free))
0x000ba550:20e5:	vector_memcpy(s0xffffffffffffff10(0x000b9de0:1871),s6(0x000b9dfe:574),a2(free))
0x000ba550:20e5:	vector_memcpy(s0xffffffffffffff10(0x000b9de0:1871),s6(0x000b9dfe:574),a2(free))
```

Where is that `free` coming from?  It looks like Ghidra will assign an address to a pcodeop
that does not fall within the address range for that block.  Tighten up the definition of `VectorMatcher::isDefinedInLoop` and the free parameter is no longer there.

#### whisper_wrap_segment debugging

This section explores segfaults thrown during a datatest built from `whisper_wrap_segment`:

```c
void whisper_wrap_segment(void*, void*, int, int); // loaded at 0xb97c0
```

Run under valgrind to see we have use-after-free problem.

```console
$ SLEIGHHOME=/opt/ghidra_12.0_DEV/ DECOMP_PLUGIN=/tmp/libriscv_vector.so valgrind --num-callers=500 /opt/ghidra_12.0_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest < test/whisper_sample_5.ghidra > /tmp/whisper_sample_5.testlog
==353775== Memcheck, a memory error detector
==353775== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==353775== Using Valgrind-3.25.1 and LibVEX; rerun with -h for copyright info
==353775== Command: /opt/ghidra_12.0_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile_datatest
==353775==
==353775== Invalid read of size 4
==353775==    at 0xA0DBA8: ghidra::FlowBlock::getIndex() const (block.hh:160)
==353775==    by 0xA0AC52: ghidra::BlockIf::scopeBreak(int, int) (block.cc:3054)
...
==353775==    by 0xA04CD5: ghidra::BlockGraph::scopeBreak(int, int) (block.cc:1275)
==353775==    by 0xA04CD5: ghidra::BlockGraph::scopeBreak(int, int) (block.cc:1275)
==353775==    by 0xA22470: ghidra::ActionFinalStructure::apply(ghidra::Funcdata&) (blockaction.cc:2201)
...
==353775==  Address 0x8556698 is 40 bytes inside a block of size 128 free'd
==353775==    at 0x4842E78: operator delete(void*, unsigned long) (vg_replace_malloc.c:1181)
==353775==    by 0xA1B2B2: ghidra::BlockDoWhile::~BlockDoWhile() (block.hh:711)
==353775==    by 0x727FBCA: ghidra::VectorMatcher::removeDoWhileWrapperBlock(ghidra::BlockBasic*) (vector_matcher.cc:671)

```

Current guess: the `DoWhile` parent is not the only place referencing a `DoWhile` block.  It can also be referenced in the list of an If block and possibly a goto block.  We need to replace *all* list references.

We need to find smaller test cases.  Run Ghidra with the plugin, exporting all functions as C.  We get
51 exceptions.  Collect some of these and identify the function throwing the exception.

| Address| Function | Size |
|--------|----------|------|
| 0x00020fd0 | main | 10844 |
| 0x0002a606 | drwav__on_write_memory | 398 |
| 0x0003e604 |  |  |
| 0x00040aba |  |  |
| 0x00041596 | gpt_split_words | 1928 |
| 0x00041d9e |  |  |
| 0x000454ce | __copy_move_a2<false,... |	666  |
| 0x0004e81c | lookup_collatename<char_const*> | 738 |

Pick the smallest of these, `drwav__on_write_memory`, and continue.
The smaller size makes debugging much easier, identifying goto-like links from an IfBlock to the DoWhile block.
Add some more setter methods to the Ghidra patch, and get a successful decompilation.

Returning to the `main` decompilation, we find several goto blocks referencing a dowhile block we intend to
delete.  One more Ghidra setter method added, with added recursion into the `gototarget`.

Now all test cases complete without a decompiler exception - other than those datatests that fail without a plugin present.

Load the plugin into the Ghidra GUI path, and collect overall statistics:

| transform | instances completed |
|-----------|---------------------|
| vector_memset | 468 |
| vector_memcpy | 1113 |


The code has some truly ugly components, which we will address later during refactoring.