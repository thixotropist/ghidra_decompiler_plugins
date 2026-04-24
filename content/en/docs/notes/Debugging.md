---
title: Debugging
description: refactoring made a lot of improvements, and cleared away bad code that somehow worked. How do we address the new and improved failures?
weight: 110
---

`dpdk_sample_1`, `whisper_sample_5`, `whisper_sample_12`,  and `whisper_main` currently fail.  Compare the failure modes to see where to start?

## Survey the four failed tests to look for a place to start

### dpdk_sample_1

* `Low-level ERROR: Free varnode has multiple descendants`
* no errors in logging
* no free varnodes warned
* vector_strcmp located, but not transformed at 0x2ab512
* possible problem with `a5(0x002ab512:3ff) = a5(0x002ab510:49) ? c0x0c20(free)`

```text
0x2ab70a: [60] u0x10000173(0x002ab70a:600) = c0x0c20(free) ? c0x0c20(0x002ab714:528) ? c0x0c20(free)
0x2ab70a: [60] a0(0x002ab70a:601) = a0(0x002ab706:156) ? a0(0x002ab714:15d) ? a0(0x002ab622:105)
0x2ab714: [61] c0x0c20(0x002ab714:528) = c0x0c20(free) [] i0x002ab714:15d(free)
         ↑↑↑ Removing this opcode
```

⇒Possibly change removal of c0x0c20 MULTIEQUAL nodes to replace descendents with `c0x0c20(i)`?

Done.  this sample now processes without a failure.

### whisper_sample_5

* segfault in `ghidra::FlowBlock::getIn`
* 21 transforms possible
* error logged:
    ```text
    PcodeOps with free Varnodes still exist - decompiler will abort:
    Pcode at 0xb9d64:52c  s2(0x000b9d64:52c) = s2(0x000b9c94:4bd) + a5(free)
    ```
* MULTIEQUAL PcodeOp mistakenly deleted, not consumed in loop.  Note an input Varnode is output Varnode.
    ```text
    a5(0x000b9d50:2436) = a5(0x000b9d50:2436) ? a5(0x000b9d48:51f) ? s10(0x000b9cfa:1208)
    ```

Modify the code so that this MULTIEQUAL op is not treated as
modifying the loop.  We then get segfaults similar to the following.

### whisper_sample_12

* segfault in `ghidra::FlowBlock::getIn`
* 33 transforms possible
* multiple logged warnings, no logged errors

### whisper_main

* segfault in `ghidra::FlowBlock::getIn`
* multiple logged warnings, no logged errors
* 9 transforms possible, 4 effected

## Examine Edge transformations

The three remaining failures all have a common signature, a vector assertion error:

    Assertion '__n < this->size()' failed
    ghidra::FlowBlock::getIn(int) const (block.hh:306)

This is a single-line method:

```c
FlowBlock::getIn(int)
{
    return intothis[i].point;
}
```

The backtrace shows that this error is caught outside of our plugin code, during `ActionMergeRequired`:

```text
Process terminating with default action of signal 6 (SIGABRT): dumping core
   at 0x4CAD3CC: __pthread_kill_implementation (pthread_kill.c:44)
   by 0x4C5315D: raise (raise.c:26)
   by 0x4C3A6CF: abort (abort.c:77)
   by 0x48AC083: std::__glibcxx_assert_fail(char const*, int, char const*, char const*) (assert_fail.cc:41)
   by 0xA4AE41: std::vector<ghidra::BlockEdge, std::allocator<ghidra::BlockEdge> >::operator[](unsigned long) const (stl_vector.h:1282)
   by 0xA49D5E: ghidra::FlowBlock::getIn(int) const (block.hh:306)
   by 0xAB502B: ghidra::Cover::addRefPoint(ghidra::PcodeOp const*, ghidra::Varnode const*) (cover.cc:607)
   by 0xBC010C: ghidra::Merge::eliminateIntersect(ghidra::Varnode*, std::vector<ghidra::BlockVarnode, std::allocator<ghidra::BlockVarnode> > const&) (merge.cc:505)
   by 0xBC0751: ghidra::Merge::unifyAddress(std::_Rb_tree_const_iterator<ghidra::Varnode*>, std::_Rb_tree_const_iterator<ghidra::Varnode*>) (merge.cc:600)
   by 0xBC0955: ghidra::Merge::mergeAddrTied() (merge.cc:632)
   by 0xA9EE15: ghidra::ActionMergeRequired::apply(ghidra::Funcdata&) (coreaction.hh:370)
   by 0xA1BBFA: ghidra::Action::perform(ghidra::Funcdata&) (action.cc:319)
```

Gather data on what `ActionMergeRequired` is likely attempting:
* This Action follows the `actcleanup` Action, and triggers after all of our plugin rules have finished.  Its code includes:
    ```c
    // \brief Make required Varnode merges as dictated by CPUI_MULTIEQUAL, CPUI_INDIRECT, and addrtied property
    data.getMerge().mergeAddrTied(); data.getMerge().groupPartials(); data.getMerge().mergeMarker(); return 0; }
    ```
*  `Merge::mergeAddrTied` is more complicated, failing in `unifyAddress`:
    ```c
    /// \brief Force the merge of address tried Varnodes
    /// For each set of address tied Varnodes with the same size and storage address, merge
    /// them into a single HighVariable. The merges are forced, so any Cover intersections must
    /// be resolved by altering data-flow, which involves inserting additional COPY ops and
    /// unique Varnodes.
    void Merge::mergeAddrTied(void)
    {
        ...
        VarnodeLocSet::const_iterator startiter;
        vector<VarnodeLocSet::const_iterator> bounds;
        for(startiter=data.beginLoc();startiter!=data.endLoc();) {
            ...
            unifyAddress(startiter,bounds[max]);
            ...
        }
    }
    ```
* `Merge::unifyAddress` fails in `eliminateIntersect`:
    ```c
    /// \brief Make sure all Varnodes with the same storage address and size can be merged
    ///
    /// The list of Varnodes to be merged is provided as a range in the main location sorted
    /// container.  Any discovered intersection is \b snipped by splitting data-flow for one of
    /// the Varnodes into two or more flows, which involves inserting new COPY ops and temporaries.
    /// \param startiter is the beginning of the range of Varnodes with the same storage address
    /// \param enditer is the end of the range
    void Merge::unifyAddress(VarnodeLocSet::const_iterator startiter,VarnodeLocSet::const_iterator enditer)

    {
    VarnodeLocSet::const_iterator iter;
    Varnode *vn;
    vector<Varnode *> isectlist;
    vector<BlockVarnode> blocksort;

    for(iter=startiter;iter!=enditer;++iter) {
        vn = *iter;
        if (vn->isFree()) continue;
        isectlist.push_back(vn);
    }
    blocksort.resize(isectlist.size());
    for(int4 i=0;i<isectlist.size();++i)
        blocksort[i].set(isectlist[i]);
    stable_sort(blocksort.begin(),blocksort.end());

    for(int4 i=0;i<isectlist.size();++i)
        eliminateIntersect(isectlist[i],blocksort);
    }
    ```
* `eliminateIntersect` is longer, failing when 'adding a reference point'

So it is likely the current code is violating some consistency contract regarding edges and varnodes.

We have several possible paths forward:
1. review the native code to identify edge and varnode containers and try to determine the consistency rules we are violating.
    * For instance, we might be copying Varnode pointers rather than copying Varnodes themselves.
    * Or we can add inspection code to display all Varnodes in a function before and after transforms,
      so that we can observe rules and differences.
2. set up `gdb` to identify the precise ops, blocks, and edges triggering this specific failure.
3. patch logging messages into `merge.cc` to trace and annotate the failure.
4. review the existing plugin code to see if these errors persist when no edge editing is performed.
5. apply the failing plugin to export the entire program to C, then searching the results to find the smallest function showing the same
   failure.  Turn this into a persistent regression test.

Options 2, 3, and 4 all address a specific error, and don't necessarily help us with later errors.
Let's start with option 1 and add an `auditVarnodes` method to the Inspector class, where we can start to understand the internal consistency
rules we must always follow.

Run the varnode audit on riscv_csr before and after the CSR transforms, given the whisper_main exemplar:
* a total of 140559 varnodes before and after
* no visible duplication of varnode addresses

We can run the full plugin on main if allowing for a single loop transform, so the CSR rule is not likely to be the immediate problem.
Collect audit data at the end of every memcpy transform, stopping after the second transform.

Comparing the audit data after the second memcpy transform and the postCSR rule and matching on Varnode pointer value, we see some likely problems:

* s1(0x00021454:2a12)⇒s1(free)
* s1(0x0002145e:1708)⇒s1(free)
* a3(0x00021454:30f5)⇒a3(free)
* a3(0x00021464:170b)⇒a3(free)
* a4(0x00021454:32c0)⇒a4(free)
* a4(0x0002145c:1707)⇒a4(free)
* a5(0x00021454:1704)⇒a5(free)
* v1(0x0002108e:94)⇒v1(free)
* v1(0x000211ae:13e)⇒v1(free)
* v1(0x000212fe:1626)⇒v1(free)
* v1(0x00021458:1706)⇒v1(free)

etc.

Now run a proper control, resetting `TRANSFORM_LIMIT_LOOPS = 2` down to `TRANSFORM_LIMIT_LOOPS = 1`  We see similar free varnodes on the list
without a crash, so that is not likely the root problem.  These Varnodes are likely already on the `dead` list.

Add an audit for the BlockGraph generated by `Funcdata::getBasicBlocks`, recursing that tree and checking that all outbound edges have a matching inbound edge.

That showed no initial results.  Perhaps we need an audit of `Funcdata::getStructure` instead, as that holds control flow data.

Get more methodical to isolate the fault.
1. decrease `TRANSFORM_LIMIT_LOOPS` until the segfault no longer occurs
2. increase `TRANSFORM_LIMIT_LOOPS` by one, so that analysis on the failing transform is completely logged but the transform is aborted with no changes.
3. inspect the log files for any anomalies
4. inspect Ghidra GUI - with no plugin - for anything different in or near this vector loop
5. increase `TRANSFORM_LIMIT_LOOPS` by one, inspecting the log file for any warnings or anomalies.

Applying that to the current fault shows that a normal-looking `vector_memcpy` transform is identified at 0x21552.  The Decompiler window shows
a somewhat unusual control structure:

```c
 {
     ...
LAB_ram_00021552:
   do {
     lVar10 = vsetvli_e8m1tama(pwVar24);
     auVar46 = vle8_v(puVar29);
     pwVar24 = (whisper_params *)((long)pwVar24 - lVar10);
     puVar29 = puVar29 + lVar10;
     vse8_v(auVar46,ppwVar11);
     ppwVar11 = (whisper_params **)((long)ppwVar11 + lVar10);
   } while (pwVar24 != (whisper_params *)0x0);
 }
 else {
LAB_ram_00021a2a:
     ppwVar11 = local_538;
     pwVar18 = (whisper_params *)((undefined8 *)(whisper_params._416_8_ + lVar10))[1];
     puVar29 = *(undefined1 **)(whisper_params._416_8_ + lVar10);
     if ((whisper_params *)0xf < pwVar18) {
LAB_ram_00021f9a:
        local_8a8 = local_538;
        local_548 = local_8a8;
            /* try { // try from 00021f9e to 00021fa1 has its CatchHandler @ 00023bf2 */
        ppwVar11 = (whisper_params **)func_0x0001fad0(&pwVar18->field_0x1);
        pwVar24 = pwVar18;
        local_538[0] = pwVar18;
        local_548 = ppwVar11;
     goto LAB_ram_00021552;
   }
   ...
}
```

We need to check is whether our BlockGraphEditor handles that `goto` placement properly.

## Survey all of whisper.cpp for errors

First, we need to fix a major regression - the plugin no longer works with the Ghidra GUI.
Apparently the API presented by the datatest driver is slightly extended from that available to the GUI.
That's not hard to fix.

The real next step is to run all of whisper-cpp through the GUI, exporting to C, and collecting
a checklist of things that work and things to fix.

1708 functions processed, roughly 63 errors, or a 4% error rate.

| function | size (bytes) |  error |
| -------- | ------- | ----- |
| _GLOBAL__sub_I_common.cpp | 960 | Unable to force merge of op at 0x00020748:8a2 |
| __static_initialization_and_destruction_0 | 718 | Unable to force merge of op at 0x00020c8a:763 |
| main | 10844 | Unable to force merge of op at 0x00021552:1882c |
| _GLOBAL__sub_I_cli.cpp | 956 | Unable to force merge of op at 0x000240e0:879 |
| drwav__on_read_memory | 72 | Free varnode has multiple descendants |
| drwav__on_write_memory | 398 | Free varnode has multiple descendants |
| drwav_buffer_reader_read_u16 | 98 | Missing function callspec |
| get_next_arg | 278 | Unable to force merge of op at 0x00037f10:182 |
| read_wav | 2906 | Unable to force merge of op at 0x000392dc:1d94 |
| to_timestamp[abi:cxx11] | 394 | Unable to force merge of op at 0x0003a382:1de |
| gpt_vocab_init | 538 | Unable to force merge of op at 0x0003c564:4a3 |
| speak_with_file | 2274 | Unable to force merge of op at 0x0003cba4:1aeb |
| sam_params_parse | 1648 | Unable to force merge of op at 0x0003d0ba:1027 |
| gpt_params_parse | 3040 | Unable to force merge of op at 0x0003f1fc:2125 |
| gpt_tokenize | 4378 | Unable to force merge of op at 0x000427e2:4a71 |
| __stoa<float,float,char> | 116 | Unable to force merge of op at 0x00044278:2f3 |
| _M_insert_character_class_matcher<true,true> |  | Missing function callspec |
| _M_insert_character_class_matcher<true,false> |  | Missing function callspec |
| _M_insert_character_class_matcher<false,true> |  | Missing function callspec |
| _M_insert_bracket_matcher<true,true> |  | Missing function callspec |
| _M_insert_bracket_matcher<true,false> |  | Missing function callspec |
| _M_insert_bracket_matcher<false,true> |  | Missing function callspec |
| _M_expression_term<false,false> |  | Missing function callspec |
| _M_insert_bracket_matcher<false,false> |  | Missing function callspec |
| _M_disjunction |  | Missing function callspec |
| _M_atom | 1648 | Missing function callspec |
| _Compiler |  | Missing function callspec |
| _M_assertion |  | Missing function callspec |
| vector | 152 | Unable to force merge of op at 0x0005a10e:26d |
| get_symbol_id |  | nable to force merge of op at 0x0005af88:939 |
| generate_symbol_id |  | Unable to force merge of op at 0x0005b428:15c6 |
| print_grammar |  | Unable to force merge of op at 0x0005c446:2d93 |
| append |  | Unable to force merge of op at 0x0006073c:3c6 |
| operator+ |  | Unable to force merge of op at 0x000622f8:3cc |
| whisper_params_parse |  | Unable to force merge of op at 0x00062b5c:47ae |
| output_wts |  | Unable to force merge of op at 0x00065ac0:7b86 |
| gguf_get_meta_data | 116 | Missing function callspec |
| _M_range_insert... |  | Unable to force merge of op at 0x000a856c:434 |
| to_timestamp |  | Unable to force merge of op at 0x000aa922:1de |
| insert |  | Unable to force merge of op at 0x000ac8b4:521 |
| whisper_lang_id |  | Unable to force merge of op at 0x000aebe6:9d7 |
| whisper_exp_compute_token_level_timestamps |  | Unable to force merge of op at 0x000af48e:156a |
| whisper_init_from_buffer_with_params_no_state |  | Missing function callspec |
| whisper_init_from_buffer |  | Missing function callspec |
| whisper_init_from_buffer_no_state |  | Missing function callspec |
| whisper_init |  | Missing function callspec |
| whisper_init_no_state |  | Missing function callspec |
| whisper_wrap_segment |  | Unable to force merge of op at 0x000ba13a:2022 |
| whisper_bench_ggml_mul_mat_str |  | Unable to force merge of op at 0x000bb242:37fc |
| whisper_bench_memcpy_str |  | Unable to force merge of op at 0x000bd58e:13f5 |
| whisper_init_from_file |  | Missing function callspec |
| whisper_init_from_file_no_state |  | Missing function callspec |
| operator= |  | Unable to force merge of op at 0x000bfd5a:8d6 |
| operator= |  | Unable to force merge of op at 0x000c01f2:87c |
| whisper_process_logits |  | Unable to force merge of op at 0x000c32f0:5dc7 |
| _M_run |  | Missing function callspec |
| tokenize |  | Unable to force merge of op at 0x000c4dd6:2a33 |
| whisper_tokenize |  | Unable to force merge of op at 0x000c53f6:346 |
| whisper_full_parallel |  | Missing function callspec |
| __do_str_codecvt... |  | Unable to force merge of op at 0x000cf652:921 |
| utf16_to_utf8 |  | Unable to force merge of op at 0x000cfe6e:4a6 |
| get_executable_path |  | Unable to force merge of op at 0x000d0906:ef4 |
| ggml_backend_cpu_reg_get_device |  | Missing function callspec |
| drwav__metadata_process_chunk | 6586 | Exception while decompiling ram:00032aee: Decompiler process died |
| to_string | 534 | Exception while decompiling ram:000cbaca: Decompiler process died |

### start with the smallest failure

`drwav__on_read_memory` is only 72 bytes long and throws a `free varnode` error.

The plugin generates
```text
Basic Block 1 0x0002a5dc-0x0002a5e0
0x0002a5dc:1f:  u0x00030300(0x0002a5dc:1f) = a0(i) + #0xc0
0x0002a5dc:20:  a5(0x0002a5dc:20) = *(ram,u0x00030300(0x0002a5dc:1f))
0x0002a5e0:22:  a5(0x0002a5e0:22) = a5(0x0002a5dc:20) + a4(0x0002a5c6:c)
Basic Block 2 0x0002a5e2-0x0002a5f4
0x0002a5f4:4f:  vector_memcpy(a1(i),a5(0x0002a5e0:22),a2(0x0002a5cc:11))
Basic Block 3 0x0002a5f6-0x0002a604
0x0002a5f6:2e:  u0x00030300(0x0002a5f6:2e) = a0(i) + #0xd0
0x0002a5f6:2f:  a5(0x0002a5f6:2f) = *(ram,u0x00030300(0x0002a5f6:2e))
0x0002a5fc:36:  a5(0x0002a5fc:36) = a5(0x0002a5f6:2f) + a2(0x0002a5cc:11)
0x0002a5fe:38:  u0x00031000(0x0002a5fe:38) = a0(i) + #0xd0
0x0002a5fe:39:  *(ram,u0x00031000(0x0002a5fe:38)) = a5(0x0002a5fc:36)
0x0002a604:41:  gp(0x0002a604:41) = gp(0x0002a5be:3e)
0x0002a604:48:  j{0x00002058,0x00002050}:10(0x0002a604:48) = CONCAT88(a1(free),a2(0x0002a5cc:11))
0x0002a604:3d:  return(#0x0) j{0x00002058,0x00002050}:10(0x0002a604:48)
```

Ghidra without the plugin decompiles as:

```c
/* drwav__on_read_memory(void*, void*, unsigned long) */

undefined1  [16] drwav__on_read_memory(void *param_1,void *param_2,ulong param_3)
{
  undefined1 auVar1 [16];
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  undefined1 auVar6 [32];
  undefined1 auVar7 [16];

  gp = &__global_pointer$;
  lVar2 = minu(*(long *)((long)param_1 + 200) - *(long *)((long)param_1 + 0xd0),param_3);
  if (lVar2 == 0) {
    auVar1._8_8_ = 0;
    auVar1._0_8_ = param_2;
    return auVar1 << 0x40;
  }
  lVar5 = *(long *)((long)param_1 + 0xc0) + *(long *)((long)param_1 + 0xd0);
  lVar3 = lVar2;
  do {
    lVar4 = vsetvli_e8m1tama(lVar3);
    auVar6 = vle8_v(lVar5);
    lVar3 = lVar3 - lVar4;
    lVar5 = lVar5 + lVar4;
    vse8_v(auVar6,param_2);
    auVar7._8_8_ = (void *)((long)param_2 + lVar4);
    param_2 = auVar7._8_8_;
  } while (lVar3 != 0);
  *(long *)((long)param_1 + 0xd0) = *(long *)((long)param_1 + 0xd0) + lVar2;
  auVar7._0_8_ = lVar2;
  return auVar7;
}
```

Ghidra has somehow decided that this function returns a 16 byte result in registers a0 and a1, so it
generates a concatenation PcodeOp (probably `CPUI_PIECE`).  We can probably fix this by detecting the
assumed dependency early and aborting the transform.  If the user corrects the signature to an uint8 then
the transform should be performed.

It appears that `drwav__on_write_memory` has the same issue.