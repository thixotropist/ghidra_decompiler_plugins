/*
 * Advanced debugging benefits from differential testing, where one sample produces the failure
 * and a minimally-different sample produces success.  In this case study
 * Ghidra throws "Low-level Error: Could not find address-tied varnode" during decompilation
 * for roughly 35 functions out of a 1700 function executable.  To derive a differential
 * test from that the steps are:
 * 1. Survey the 35 functions for the smallest function showing the fault, in this case `get_next_arg`.
 * 2. Export the assembly listing to a new file `get_next_arg.S`
 * 3. Remove Ghidra annotations to give vanilla Gnu assembler syntax
 *    a. replace `param_{n}` with `a{n-1}`
 *    b. remove leading address fields
 *    c. remove `=>...` annotations
 * 4. Compile to a sharable object file and load into Ghidra
 * 5. Selectively patch the binary to isolate immaterial code and instructions triggering the fault
 * 6. Wrap the assembly code in a macro with two arguments: a name suffix and a flags variable
 * 7. Invoke the macro twice, once with a `_fail` suffix and flags producing the observed fault
 *    and once with a `_pass` suffix and flags enabling correct decompilation.
 * 8. Compile to a sharable object file and load into Ghidra.  You should see
 *    two functions with and without the observed fault.
 *
 * In the example below:
 *    * the `ENABLE_ERROR_EXIT` bit is zero for both pass and fail, removing
 *      extraneous code not related to the fault.
 *    * the DISABLE_JAL_NEW bit is zero for fail and one for pass, effectively
 *      replacing a Jump and Link instruction with a No-Op instruction.
 */

ENABLE_ERROR_EXIT = 0x01
DISABLE_JAL_NEW = 0x02

.section .text
.macro get_next_arg suffix flags=0
.type get_next_arg_\suffix STT_FUNC
.globl get_next_arg_\suffix
get_next_arg_\suffix:
     c.addi16sp                     sp,-0x30
     c.sdsp                         s0,0x20(sp)
     c.sdsp                         ra,0x28(sp)
     c.addi4spn                     s0,sp,0x30
     lw                             a6,0x0(a1)
     c.mv                           t1,a0
     c.mv                           a7,a2
     addiw                          a0,a6,0x1
     bge                            a0,a2,0f
     sh3add                         a6,a6,a3
     ld                             a6,0x8(a6)
     li                             a2,0x2d
     lbu                            t3,0x0(a6)
     bne                            t3,a2,1f
0:
.if \flags & 0x01
     auipc                          a2,0x10b
     ld                             a2,-0x644(a2)
     c.ld                           a0,0x0(a2)
     auipc                          a1,0xc3
     addi                           a1,a1,-0x4ae
     c.mv                           a2,a4
     sd                             a5,-0x28(s0)
     sd                             a3,-0x20(s0)
     sd                             a7,-0x18(s0)
     jal                            ra,fprintf
     ld                             a0,-0x18(s0)
     ld                             a2,-0x28(s0)
     ld                             a1,-0x20(s0)
     jal                            ra,gpt_print_usage
     c.li                           a0,0x0
     jal                            ra,exit
.else
.rept 29
     c.nop
.endr
.endif
1:
     c.sw                           a0,0x0(a1)
     addi                           a0,t1,0x10
     sd                             a0,0x0(t1)
     c.li                           a4,0x0
     c.mv                           a5,a6
2:
     vsetvli                        a3,zero,e8,m1,ta,ma
     c.add                          a5,a4
     vle8ff.v                       v1,(a5)
     vmseq.vi                       v1,v1,0x0
     csrr                           a4,vl
     vfirst.m                       a2,v1
     blt                            a2,zero,2b
     c.add                          a5,a2
     sub                            a5,a5,a6
     c.li                           a4,0xf
     bltu                           a4,a5,4f
     c.li                           a4,0x1
     beq                            a5,a4,7f
     c.bnez                         a5,5f
3:
     sd                             a5,0x8(t1)
     c.add                          a0,a5
     sb                             zero,0x0(a0)
     c.ldsp                         ra,0x28(sp)
     c.ldsp                         s0,0x20(sp)
     c.mv                           a0,t1
     c.addi16sp                     sp,0x30
     ret
4:
     addi                           a0,a5,0x1
     sd                             t1,-0x28(s0)
     sd                             a6,-0x20(s0)
     sd                             a5,-0x18(s0)
.if \flags&0x02
     c.nop
     c.nop
.else
     jal                            ra,dummy_new
.endif
     ld                             t1,-0x28(s0)
     ld                             a5,-0x18(s0)
     ld                             a6,-0x20(s0)
     sd                             a0,0x0(t1)
     sd                             a5,0x10(t1)
5:
     c.mv                           a3,a5
6:
     vsetvli                        a4,a3,e8,m1,ta,ma
     vle8.v                         v1,(a6)
     c.sub                          a3,a4
     c.add                          a6,a4
     vse8.v                         v1,(a0)
     c.add                          a0,a4
     c.bnez                         a3,6b
     ld                             a0,0x0(t1)
     c.j                            3b
7:
     lbu                            a4,0x0(a6)
     c.add                          a0,a5
     sd                             a5,0x8(t1)
     sb                             a4,0x10(t1)
     sb                             zero,0x0(a0)
     c.ldsp                         ra,0x28(sp)
     c.ldsp                         s0,0x20(sp)
     c.mv                           a0,t1
     c.addi16sp                     sp,0x30
     ret

fprintf:
     ret
dummy_new:
     ret
gpt_print_usage:
     ret
exit:
     ret
.endm
