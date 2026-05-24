.section .text
.macro nfp_net_get_eeprom suffix flags=0xffff
.type nfp_net_get_eeprom_\suffix STT_FUNC
.globl nfp_net_get_eeprom_\suffix

.globl nfp_net_get_port_mac_hwinfo
.extern nfp_net_get_hw

ENABLE_VECTOR_OPS = 0x0001
ENABLE_JAL = 0x0002
ENABLE_OTHER_BLOCKS = 0x0004
ENABLE_OTHER_INSTRS = 0x0008

nfp_net_get_eeprom_\suffix:
  c.addi16sp  sp,-0x40
  c.sdsp      ra,0x38(sp)
  c.sdsp      s2,0x20(sp)
.if \flags & ENABLE_OTHER_BLOCKS
  c.lw        a5,0xc(a1)
  c.beqz      a5,6f
.endif
  c.ld        a4,0x48(a0)
  c.lui       a5,0x1
  c.sdsp      s0,0x30(sp)
  c.add       a5,a4
  lw          a5,0x57c(a5)
  c.sdsp      s1,0x28(sp)
  c.sdsp      s3,0x18(sp)
  c.andi      a5,0x10
  c.ld        a3,0x50(a0)
  c.ld        a4,0x60(a4)
  c.mv        s0,a1
.if \flags & ENABLE_OTHER_BLOCKS
  c.bnez      a5,4f
.endif
  lbu         a1,0x359(a4)
0:
  c.addi4spn  s1,sp,0x8
  c.mv        s3,a0
.if \flags & ENABLE_JAL
  c.mv        a2,s1
  c.mv        a0,a3
  jal         ra,nfp_net_get_port_mac_hwinfo
.else
  c.nop
  c.nop
  nop
  c.mv        a0,s3
.endif
  c.mv        s2,a0
  c.bnez      a0,5f
  c.mv        a0,s3
.if \flags & ENABLE_JAL
  jal         ra,nfp_net_get_hw
.else
  c.li        a0,0x10
.endif
  lhu         a5,0x78(a0)
  lhu         a1,0x7a(a0)
  lwu         a2,0x8(s0)
  slliw       a5,a5,0x10
  c.ld        a3,0x0(s0)
  lwu         a4,0xc(s0)
  c.or        a5,a1
  c.sw        a5,0x10(s0)
  c.add       a2,s1
1:
.if \flags & ENABLE_VECTOR_OPS
  vsetvli     a5,a4,e8,m1,ta,ma
  vle8.v      v1,(a2)
  c.sub       a4,a5
  c.add       a2,a5
  vse8.v      v1,(a3)
  c.add       a3,a5
.else
  c.sub       a4,a5
.endif
  c.bnez      a4,1b
2:
  c.ldsp      s0,0x30(sp)
  c.ldsp      s1,0x28(sp)
  c.ldsp      s3,0x18(sp)
3:
  c.ldsp      ra,0x38(sp)
  c.mv        a0,s2
  c.ldsp      s2,0x20(sp)
  c.addi16sp  sp,0x40
  ret
.if \flags & ENABLE_OTHER_BLOCKS
4:
  c.lw        a1,0xc(a4)
  c.j         0b
.endif
5:
  li          s2,-0x5f
  c.j         2b
.if \flags & ENABLE_OTHER_BLOCKS
6:
  c.li        s2,-0x16
  c.j         3b
.endif
.endm

nfp_net_get_eeprom baseline
nfp_net_get_eeprom no_vector 0xfffe
nfp_net_get_eeprom no_subrs 0xfffc
nfp_net_get_eeprom minimal 0x0000

.type nfp_synthetic STT_FUNC
.globl nfp_synthetic

nfp_synthetic:
  c.addi16sp                     sp,-0x40
  c.sdsp                         ra,0x38(sp)
  c.sdsp                         s2,0x20(sp)
  c.sdsp                         s0,0x30(sp)
  c.sdsp                         s1,0x28(sp)
  c.mv                           s0,a1
  c.li                           s2,0x04
0:
  c.addi4spn                     s1,sp,0x8
  jal                            ra,dummy
  c.mv                           s2,a0
  c.bnez                         a0,5f
  c.li                           a0,0x10
  c.li                           a5,0x1
  c.li                           a4,0x7
1:
  c.sub                          a4,a5
  c.bnez                         a4,1b
2:
  c.ldsp                         s0,0x30(sp)
  c.ldsp                         s1,0x28(sp)
  c.ldsp                         ra,0x38(sp)
  c.mv                           a0,s2
  c.ldsp                         s2,0x20(sp)
  c.addi16sp                     sp,0x40
  ret

5:
  li                             s2,-0x5f
  c.j                            2b

dummy:
  add                          a0,a1,a2
  ret