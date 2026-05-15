---
title: Stress testing
description: Work up a case study involving a difficult function
weight: 130
---

The function ` drwav__metadata_process_chunk` currently kills the decompiler when invoked by the GUI.  Exporting it to
`whisper_sample_19` generates *no* errors.  The function has enough complex state that we need to work a bit harder
to isolate the problem or problems.

>Note: `vector_strlen` is causing several problems currently, likely due to dependency issues when processing the loop epilog.

## Localizing a decompiler exception

The GUI claims  `Exception while decompiling ram:00032aee: Decompiler process died`.

Find and analyze the coredump:

```console
# coredumpctl list|tail
...
Mon 2026-05-11 15:39:26 EDT  771046  1000 1000 SIGABRT present  /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile
# coredumpctl info 771046
...
Executable: /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile
...
Storage: /var/lib/systemd/coredump/core.decompile.1000.2e8a58190b06496392b4ff2e56eb408f.771046.1778528366000000.zst (present)
# zstd -d  /var/lib/systemd/coredump/core.decompile.1000.2e8a58190b06496392b4ff2e56eb408f.771046.1778528366000000.zst -o /tmp/core
# gdb  /opt/ghidra_12.1_DEV/Ghidra/Features/Decompiler/os/linux_x86_64/decompile /tmp/core
...
(gdb) bt
#0  __pthread_kill_implementation (threadid=<optimized out>, signo=signo@entry=6, no_tid=no_tid@entry=0) at pthread_kill.c:44
#1  0x00007f277c67a8d3 in __pthread_kill_internal (threadid=<optimized out>, signo=6) at pthread_kill.c:89
#2  0x00007f277c61f48e in __GI_raise (sig=sig@entry=6) at ../sysdeps/posix/raise.c:26
#3  0x00007f277c6067b3 in __GI_abort () at abort.c:77
#4  0x00007f277c80b646 in std::__glibcxx_assert_fail (file=<optimized out>, line=<optimized out>, function=<optimized out>, condition=<optimized out>) at ../../../../../libstdc++-v3/src/c++11/assert_fail.cc:41
#5  0x00007f277c415f0a in std::vector<ghidra::Varnode*, std::allocator<ghidra::Varnode*> >::operator[] (this=0x3fba40a0, __n=1)
    at /usr/lib/gcc/x86_64-redhat-linux/16/../../../../include/c++/16/bits/stl_vector.h:1253
#6  0x00007f277c415c4f in ghidra::PcodeOp::getIn (this=0x3fba4050, slot=1) at external/+_repo_rules+ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/op.hh:156
#7  0x00007f277c41db8f in ghidra::FunctionEditor::simplifyBlocks (this=0x7ffcbb872338, opsToDelete=std::vector of length 10, capacity 10 = {...}, loopBlock=0x3f91b960, epilogBlock=0x3f91bd60,
    relatedBlocks=0x7ffcbb872088) at plugins/framework.cc:297
#8  0x00007f277c43ec85 in riscv_vector::VectorMatcher::transformStrlen (this=0x7ffcbb871e60) at plugins/vector_stdlib.cc:185
#9  0x00007f277c411278 in riscv_vector::RuleVectorTransform::applyOp (this=0x3f528e80, firstOp=0x3f7e4ed0, data=...) at plugins/rule_vector_transform.cc:146
#10 0x00000000005523a2 in ghidra::ActionPool::processOp(ghidra::PcodeOp*, ghidra::Funcdata&) ()
#11 0x000000000055255f in ghidra::ActionPool::apply(ghidra::Funcdata&) ()
#12 0x0000000000551c4f in ghidra::Action::perform(ghidra::Funcdata&) ()
#13 0x0000000000551d3f in ghidra::ActionGroup::apply(ghidra::Funcdata&) ()
#14 0x0000000000551deb in ghidra::ActionRestartGroup::apply(ghidra::Funcdata&) ()
#15 0x0000000000551c4f in ghidra::Action::perform(ghidra::Funcdata&) ()
#16 0x0000000000531103 in ghidra::DecompileAt::rawAction() ()
#17 0x0000000000530d69 in ghidra::GhidraCommand::doit() ()
#18 0x0000000000530fe2 in ghidra::GhidraCapability::readCommand(std::basic_istream<char, std::char_traits<char> >&, std::basic_ostream<char, std::char_traits<char> >&) ()
#19 0x00000000005186af in main ()
...
(gdb) frame 6
(gdb) p *this
$1 = {opcode = 0x3f534800, flags = 131152, addlflags = 0, start = {pc = {base = 0x3f482b50, offset = 212518}, uniq = 5849, order = 148102318}, parent = 0x3f91bd60, basiciter = 0x3fba4050,
  insertiter = 0x3fba4050, codeiter = non-dereferenceable iterator for std::list, output = 0x3fba4150, inrefs = std::vector of length 1, capacity 2 = {0x3fb7cd60}}

(gdb) p/x this->start.pc.offset
$2 = 0x33e26
(gdb) p/x this->start.uniq
$3 = 0x16d9
(gdb) p this->inrefs[0]
$4 = (ghidra::Varnode *) 0x3fb7cd60
(gdb) p*$4
$5 = {flags = 84410416, size = 8, create_index = 17922, mergegroup = 0, addlflags = 0, loc = {base = 0x3f482c30, offset = 8280}, def = 0x3f63a020, high = 0x0, mapentry = 0x0, type = 0x3f5334d0,
  lociter = 0x3fb7cd60, defiter = 0x3fb7cd60, descend = std::__cxx11::list = {[0] = 0x3fba4050}, cover = 0x0, temp = {dataType = 0x3f5334d0, valueSet = 0x3f5334d0}, consumed = 18446744073709551615,
  nzm = 18446744073709551615}
...
(gdb) p/x $4->def
$7 = 0x3f63a020
(gdb) p  *$7
$8 = {opcode = 0x3f534960, flags = 65536, addlflags = 2, start = {pc = {base = 0x3f482b50, offset = 212454}, uniq = 20160, order = 3570815783}, parent = 0x3f91b280, basiciter = 0x3f63a020,
  insertiter = 0x3f63a020, codeiter = non-dereferenceable iterator for std::list, output = 0x3fb7cd60, inrefs = std::vector of length 2, capacity 2 = {0x3fb420c0, 0x3fb7c600}}
(gdb) p/x $7->start.pc.offset
$9 = 0x33de6
```

Summarize:
* The exception was thrown within the plugin, at `plugins/vector_stdlib.cc:185`, when trying to fetch a PcodeOp's input Varnode from slot 1.
* The exception occurs late in a vector_strlen transformation, during the `simplifyBlocks` phase where the DoWhile wrapper is removed
* Gdb let's us examine the stack frame and see that the PcodeOp location is 0x33e26:16d9. That PcodeOp has a single input Varnode defined at 0x33de6:4ec0

So we are likely trying to read past the vector of Varnodes input to the PcodeOp at 0x33e26:16d9.

The code triggering this error is relatively new, adjusting MULTIEQUAL PcodeOps so that they have no more input Varnodes than the current Block has input edges:

```c
data.opRemoveInput(op, slot);
data.opInsertInput (op, op->getIn(goodSlot), slot);
```

This might be as simple as picking the wrong method.  Do we want `opUnsetInput` instead of `opRemoveInput`?  Yes - these lines should read instead:

```c
data.opUnsetInput(op, slot);
data.opSetInput (op, op->getIn(goodSlot), slot);
```

That clears the exception.  We now see no exceptions thrown with a full binary export,
and only two Low level errors citing a free Varnode.

## Aligning the test case and the full binary

The function `drwav__metadata_process_chunk` is now exported as `whisper_sample_19`, without
much of the state information useful in resolving heritage and type information.  Can we
bring them into better alignment, perhaps to support future regression testing?

Running the plugin via Ghidra with the full executable state available shows

* 5 vector_memcpy instances with a fixed number of bytes to move
* 4 vector_memcpy loop instances
* 3 vector_strlen loop instances

Running the plugin against `whisper_sample_19` shows
* 5 vector_memcpy instances with a fixed number of bytes to move
* 3 vector_memcpy loop instances
* 3 vector_strlen loop instances

The vector survey report suggests the number of potential transforms

* 28 vector_memcpy instances with a fixed number of bytes to move
* 4 vector_memcpy loop instances
* 4 vector_strlen loop instances

This suggests:
* The fixed vector_memcpy survey results have lots of false positives
* The additional state information to the full binary analysis allows for one additional
  vector_memcpy loop transform.  We should locate that state information and add it to the
  test case.
* One vector_strlen loop transform is blocked due to other dependencies

The vector_strlen pattern found during survey but not taken as a transform is:

```c
auVar34 = (*(code *)*param_1)(param_1[2],&local_2e0,0x20);
lVar28 = auVar34._8_8_;
if (auVar34._0_8_ == 0x20) {
  pcVar24 = (char *)0x0;
  if (local_2e0 != '\0') {
    lVar20 = 0;
    pcVar24 = &local_2df;
    do {
      vsetvli_e8m1tama(0);
      pcVar24 = pcVar24 + lVar20;
      auVar30 = vle8ff_v(pcVar24);
      auVar30 = vmseq_vi(auVar30,0);
      lVar28 = vfirst_m(auVar30);
      lVar20 = _vl;
    } while (lVar28 < 0);
    pcVar24 = pcVar24 + lVar28 + (1 - (long)&local_2df);
  }
  auVar34._8_8_ = lVar28;
```

The problem is `lVar28`, which appears as a temporary to the vector_strlen but
gets assigned to auVar34._8_8_ for mysterious reasons.

The vector_memcpy discrepancy is the function call to `drwav_buffer_read_u16` which
takes two parameters not the three parameters guessed at within `whisper_sample_19`.
Add the signature explicitly to the test case, and the discrepancy vanishes.
