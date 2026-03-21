# exercise vector_strcmp and similar transforms
# source:  whisper.cpp built with O3

.section .text

# simplest strcmp example
.global strcmp
.type strcmp, %function
strcmp:
  c.li     a2,0
0:
  vsetvli  a2,zero,e8,m1,ta,ma
  c.add    a0,a2
  vle8ff.v v1,(a0)
  c.add    a1,a2
  vle8ff.v v2,(a1)
  vmsne.vv v2,v1,v2
  vmseq.vi v1,v1,0x0
  csrr     a2,vl
  vmor.mm  v1,v1,v2
  vfirst.m t0,v1
  blt      t0,zero,0b
  c.add    a0,t0
  c.add    a1,t0
  c.lbu    a0,0x0(a0)
  c.lbu    a2,0x0(a1)
  c.sub    a0,a2
  ret

# simplest strncmp example
.global strncmp
.type strncmp, %function
strncmp:
  c.li     a3,0
0:
  vsetvli  zero,a2,e8,m1,ta,ma
  c.add    a0,a3
  vle8ff.v v1,(a0)
  c.add    a1,a3
  vle8ff.v v2,(a1)
  csrr     a3,vl
  vmsne.vv v2,v1,v2
  vmseq.vi v1,v1,0x0
  c.beqz   a3,1f
  vmor.mm  v1,v1,v2
  c.sub    a2,a3
  vfirst.m a4,v1
  blt      a4,zero,0b
  c.add    a0,a4
  c.add    a1,a4
1:
  c.lbu    a0,0x0(a0)
  c.lbu    a2,0x0(a1)
  c.sub    a0,a2
  ret

# simplest strcmpeq example
.global strcmpeq
.type strcmpeq, %function
strcmpeq:
  c.li     a2,0
0:
  vsetvli  a2,zero,e8,m1,ta,ma
  c.add    a0,a2
  vle8ff.v v1,(a0)
  c.add    a1,a2
  vle8ff.v v2,(a1)
  vmsne.vv v2,v1,v2
  vmseq.vi v1,v1,0x0
  csrr     a2,vl
  vmor.mm  v1,v1,v2
  vfirst.m t0,v1
  blt      t0,zero,0b
  c.add    a0,t0
  c.add    a1,t0
  c.lbu    a0,0x0(a0)
  c.lbu    a2,0x0(a1)
  beq      a0,a2,1f
  c.li     a0,0
  ret
1:
  c.li     a0,1
  ret

# simplest strncmpeq example
.global strncmpeq
.type strncmpeq, %function
strncmpeq:
  c.li     a3,0
0:
  vsetvli  zero,a2,e8,m1,ta,ma
  c.add    a0,a3
  vle8ff.v v1,(a0)
  c.add    a1,a3
  vle8ff.v v2,(a1)
  csrr     a3,vl
  vmsne.vv v2,v1,v2
  vmseq.vi v1,v1,0x0
  c.beqz   a3,1f
  vmor.mm  v1,v1,v2
  c.sub    a2,a3
  vfirst.m a4,v1
  blt      a4,zero,0b
  c.add    a0,a4
  c.add    a1,a4
1:
  c.lbu    a0,0x0(a0)
  c.lbu    a2,0x0(a1)
  beq      a0,a2,2f
  c.li     a0,0
  ret
2:
  c.li     a0,1
  ret

# strcmp calling sequence, added as a signature hint for Ghidra
.global strcmp_caller
.type strcmp_caller, %function
strcmp_caller:
    la     a0,string_1
    la     a1,string_2
    jal    strcmp
    ret

# strncmp calling sequence, added as a signature hint for Ghidra
.global strncmp_caller
.type strncmp_caller, %function
strncmp_caller:
    la     a0,string_1
    la     a1,string_2
    li     a2,5
    jal    strncmp
    ret

.section .rodata

string_1: .asciz "Hello!"
string_2: .asciz "HelloWorld!"
