# exercise vector_strlen and similar transforms
# source:  whisper.cpp built with O3,

.section .text

.extern no_return
.type no_return, %function

# simplest example
.global strlen_base
.type strlen_base, %function
strlen_base:
    c.li        a3,0x0
    c.mv        a5,a0
LAB_ram_000209d2:
    vsetvli     a2,zero,e8,m1,ta,ma
    c.add       a5,a3
    vle8ff.v    v1,(a5)
    vmseq.vi    v1,v1,0x0
    csrr        a3,vl
    vfirst.m    a6,v1
    blt         a6,zero,LAB_ram_000209d2
    c.add       a5,a6
    c.sub       a5,a0
    c.mv        a0,a5
    ret

.global strlen_var1
.type strlen_var1, %function
# adjust beginning of loop block and end of prolog
strlen_var1:
    c.li       a5,0x0
    c.mv       s5,a0
    bne        a0,zero,LAB_ram_000221f6
    jal        no_return
LAB_ram_000221f6:
    c.add      a0,a5                        # loop starts with add, not vset
    vsetvli    a5,zero,e8,m1,ta,ma
    vle8ff.v   v1,(a0)
    vmseq.vi   v1,v1,0x0
    csrr       a5,vl
    vfirst.m   a4,v1
    blt        a4,zero,LAB_ram_000221f6
    lbu        s10,0x0(s5)                  # not part of strlen
    c.add      a0,a4
    sub        a0,a0,s5
    ret
LAB_ram_00023054:
    c.li    a0,0x0
    ret

.global strlen_var2
.type strlen_var2, %function
# strlen_base plus possible dependency conflict
strlen_var2:
    c.addi16sp  sp,-0x20
    c.sdsp      ra,0x18(sp)
    c.sdsp      s0,0x10(sp)
    c.li        a3,0x0
    c.mv        a5,a0
LAB_tmp1:
    vsetvli     a2,zero,e8,m1,ta,ma
    c.add       a5,a3
    vle8ff.v    v1,(a5)
    vmseq.vi    v1,v1,0x0
    csrr        a3,vl
    vfirst.m    a6,v1
    blt         a6,zero,LAB_tmp1
    c.add       a5,a6
    c.sub       a5,a0
    c.mv        s0,a5
    jal         other_function
    c.add       a0,s0
    c.ldsp      s0,0x10(sp)
    c.ldsp      ra,0x18(sp)
    c.addi16sp  sp,0x20
    ret

.global other_function
.type other_function, %function
other_function:
    add     t0,a0,a1
    c.mv    a0,t0
    ret