/*
 * Generate a differential test for a Ghidra decompiler bug report
 */
.section .text

NATIVE_CSR = 0x0
PATCHED_CSR = 0x1
DEFAULT_VLENB = 32  /* a 32*8 bit vector register */
.macro TEST_CASE suffix flags=0
.type acl_merge_trie_\suffix STT_FUNC
.globl acl_merge_trie_\suffix
#define context a0
#define node_a a1
#define node_b a2
#define level a3
#define return_c a4
.extern acl_intersect_type
.extern acl_merge_trie
.extern acl_add_ptr.isra.0
.extern acl_compact_node_ptrs
.extern acl_free_node
.extern acl_dup_node

acl_merge_trie_\suffix:
    c.addi16sp     sp,-0x130
    c.sdsp         s4,0x100(sp)
    lw             s4,0x48(node_a)
    c.sdsp         s2,0x110(sp)
    c.sdsp         s7,0xe8(sp)
    c.sdsp         s9,0xd8(sp)
    c.sdsp         s11,0xc8(sp)
    c.sdsp         ra,0x128(sp)
    c.sdsp         s0,0x120(sp)
    c.sdsp         s1,0x118(sp)
    c.sdsp         s3,0x108(sp)
    c.sdsp         s5,0xf8(sp)
    c.sdsp         s6,0xf0(sp)
    c.sdsp         s8,0xe0(sp)
    c.sdsp         s10,0xd0(sp)
.if \flags & PATCHED_CSR
    li             t0,DEFAULT_VLENB
.else
    csrr           t0,vlenb
.endif
    sub            sp,sp,t0
    c.mv           s11,node_a
    c.mv           s9,node_b
    c.mv           s7,return_c
    c.mv           s2,context
    bne            s4,zero,21f
    c.ld           a5,0x70(node_a)
    lw             s3,0x30(node_a)
    c.mv           s6,level
    c.sdsp         a5,0x18(sp)
    c.mv           s8,node_a
    bne            level,zero,20f
0:
.if \flags & PATCHED_CSR
    li             a5,DEFAULT_VLENB
.else
    csrr           a5,vlenb
.endif
    c.mv           s1,a5
    addi           a5,a5,0x80
    add            s5,sp,a5
    c.mv           node_b,s5
    addi           node_a,s9,0x10
    addi           context,s8,0x10
    jal            ra,acl_intersect_type
    andi           a5,context,0x4
    c.mv           return_c,context
    beq            a5,zero,10f
    lw             a6,0x30(s9)
    lw             a5,0x38(s9)
    sw             a6,0x38(s9)
    lw             level,0x30(s8)
    lw             a7,0x38(s8)
    c.sdsp         a5,0x38(sp)
    sw             level,0x38(s8)
    beq            level,zero,9f
    slli           node_b,a6,0x20
    c.srli         node_b,0x20
    slli           s0,node_b,0x2
    c.add          s0,node_b
    addi           node_b,s1,0x78
    c.add          node_b,sp
    addi           node_a,s1,0xb0
    c.sdsp         node_b,0x20(sp)
    addiw          node_b,s6,0x1
    addi           s1,s1,0xa0
    c.sdsp         node_b,0x28(sp)
    add            node_b,sp,node_a
    c.sdsp         s11,0x50(sp)
    c.mv           s10,s9
    c.sdsp         s7,0x60(sp)
    c.slli         s0,0x3
    c.mv           s7,s3
    c.add          s1,sp
    c.mv           s3,s8
    c.sdsp         node_b,0x30(sp)
    c.sdsp         a6,0x10(sp)
    c.sdsp         a7,0x40(sp)
    c.sdsp         s5,0x48(sp)
    c.sdsp         s2,0x8(sp)
    c.li           s11,0x0
    c.mv           s9,level
    c.sdsp         s6,0x58(sp)
    c.li           s8,0x0
    c.sdsp         context,0x68(sp)
    c.j            3f
1:
    c.addiw        s7,-0x1
2:
    c.addiw        s8,0x1
    addi           s11,s11,0x28
    beq            s9,s8,8f
3:
    ld             node_b,0x40(s3)
    c.add          node_b,s11
    c.ld           node_b,0x20(node_b)
    c.beqz         node_b,1b
    c.ldsp         a5,0x10(sp)
    sd             zero,0x70(node_b)
    c.beqz         a5,2b
    c.li           s2,0x0
    c.mv           s5,s3
    c.mv           s6,s10
    c.j            5f
4:
    addi           s2,s2,0x28
    beq            s2,s0,7f
5:
    ld             node_a,0x40(s6)
.if \flags & PATCHED_CSR
    li             a5,DEFAULT_VLENB
.else
    csrr           a5,vlenb
.endif
    c.add          a5,sp
    c.add          node_a,s2
    ld             s3,0x20(node_a)
    sd             zero,0x78(a5)
    beq            s3,zero,4b
    ld             context,0x40(s5)
    c.add          context,s11
    ld             s10,0x20(context)
    beq            s3,s10,4b
    c.mv           node_b,s1
    jal            ra,acl_intersect_type
    c.andi         context,0x4
    c.beqz         context,4b
    c.mv           node_a,s10
    c.ldsp         s10,0x8(sp)
    c.ldsp         return_c,0x20(sp)
    c.ldsp         level,0x28(sp)
    c.mv           node_b,s3
    c.mv           context,s10
    jal            ra,acl_merge_trie
    bne            context,zero,18f
.if \flags & PATCHED_CSR
    li             a5,DEFAULT_VLENB
.else
    csrr           a5,vlenb
.endif
    c.add          a5,sp
    ld             s3,0x78(a5)
    beq            s3,zero,4b
    ld             return_c,0x40(s5)
    c.add          return_c,s11
    c.ld           return_c,0x20(return_c)
    beq            s3,return_c,4b
    c.mv           level,s1
    c.mv           node_a,s5
    c.mv           context,s10
    c.mv           node_b,s3
    jal            ra,acl_add_ptr.isra.0
    vsetivli       zero,0x4,e32,m1,ta,ma
    ld             node_a,0x40(s5)
    vle32.v        v1,(s1)
    ld             return_c,0x40(s6)
    add            level,node_a,s11
    vle32.v        v3,(level)
    c.add          return_c,s2
    c.ld           return_c,0x20(return_c)
    vnot.v         v1,v1
    c.ldsp         a5,0x30(sp)
    addi           context,level,0x10
    vand.vv        v1,v1,v3
    vle32.v        v2,(a5)
    vmv.s.x        v3,zero
    vse32.v        v1,(level)
    sub            return_c,return_c,s3
    sltu           return_c,zero,return_c
    addw           s7,return_c,s7
    vnot.v         v2,v2
    c.addiw        s4,0x1
    vle32.v        v4,(context)
    vand.vv        v2,v2,v4
    vor.vv         v1,v1,v2
    vse32.v        v2,(context)
    vredor.vs      v1,v1,v3
    vmv.x.s        return_c,v1
    c.bnez         return_c,4b
    slli           return_c,s8,0x2
    c.add          return_c,s8
    c.slli         return_c,0x3
    c.add          node_a,return_c
    c.ld           node_a,0x20(node_a)
    c.beqz         node_a,6f
    c.lw           return_c,0xc(node_a)
    c.addiw        return_c,-0x1
    c.sw           return_c,0xc(node_a)
    beq            return_c,zero,29f
6:
    sd             zero,0x20(level)
    addi           s2,s2,0x28
    c.addiw        s7,-0x1
    bne            s2,s0,5b
7:
    c.addiw        s8,0x1
    c.mv           s3,s5
    c.mv           s10,s6
    addi           s11,s11,0x28
    bne            s9,s8,3b
8:
    c.mv           s8,s3
    c.ldsp         a7,0x40(sp)
    c.mv           s3,s7
    c.ldsp         s5,0x48(sp)
    c.ldsp         s2,0x8(sp)
    c.ldsp         s11,0x50(sp)
    c.ldsp         s6,0x58(sp)
    c.ldsp         s7,0x60(sp)
    c.ldsp         return_c,0x68(sp)
    c.mv           s9,s10
9:
    sw             a7,0x38(s8)
    c.mv           context,s8
    c.sdsp         return_c,0x8(sp)
    jal            ra,acl_compact_node_ptrs
    c.ldsp         a5,0x38(sp)
    c.mv           context,s9
    sw             a5,0x38(s9)
    jal            ra,acl_compact_node_ptrs
    c.ldsp         return_c,0x8(sp)
    c.mv           a5,s4
10:
    c.andi         return_c,0x2
    c.beqz         return_c,13f
    lw             node_b,0x30(s9)
    c.addiw        a5,0x1
    c.beqz         node_b,13f
    vsetivli       zero,0x4,e32,m1,ta,ma
    vmv.s.x        v1,zero
    c.addi4spn     return_c,sp,0x70
    vs1r.v         v1,(return_c)
.if \flags & PATCHED_CSR
    li             return_c,DEFAULT_VLENB
.else
    csrr           return_c,vlenb
.endif
    addi           level,return_c,0xa0
    add            s10,sp,level
    addi           level,return_c,0x90
    add            s0,sp,level
    c.li           s4,0x0
    addi           return_c,return_c,0xb0
    c.sdsp         s3,0x10(sp)
    c.mv           s1,s5
    c.mv           s3,s0
    c.sdsp         a5,0x8(sp)
    c.mv           s5,s4
    add            s0,sp,return_c
11:
    ld             return_c,0x40(s9)
    slli           a5,s4,0x2
    c.add          a5,s4
    c.slli         a5,0x3
    c.add          a5,return_c
    c.add          return_c,s5
    c.ld           return_c,0x20(return_c)
    addi           level,a5,0x10
    c.beqz         return_c,12f
    vle32.v        v1,(s1)
    vle32.v        v2,(s3)
    vle32.v        v4,(a5)
    vle32.v        v3,(level)
    c.addi4spn     return_c,sp,0x70
    c.mv           level,s10
    vnot.v         v1,v1
    vnot.v         v2,v2
    c.mv           node_a,s8
    vand.vv        v1,v1,v4
    vand.vv        v2,v2,v3
    c.mv           context,s2
    vse32.v        v1,(s10)
    vse32.v        v2,(s0)
    vor.vv         v1,v1,v2
    vl1re32.v      v2,(return_c)
    vredor.vs      v1,v1,v2
    vmv.x.s        return_c,v1
    c.beqz         return_c,12f
    c.ld           node_b,0x20(a5)
    jal             ra,acl_add_ptr.isra.0
    lw             node_b,0x30(s9)
    vsetivli       zero,0x4,e32,m1,ta,ma
12:
    c.addiw        s4,0x1
    addi           s5,s5,0x28
    bltu           s4,node_b,11b
    c.ldsp         a5,0x8(sp)
    c.ldsp         s3,0x10(sp)
13:
    beq            s8,s11,14f
    c.ldsp         return_c,0x18(sp)
    beq            s8,return_c,14f
    beq            a5,zero,27f
    beq            s3,zero,25f
14:
    beq            s7,zero,16f
15:
    sd             s8,0x0(s7)
16:
    beq            s6,zero,19f
17:
    c.li           context,0x0
18:
.if \flags & PATCHED_CSR
    li             t0,DEFAULT_VLENB
.else
    csrr           t0,vlenb
.endif
    c.add          sp,t0
    c.ldsp         ra,0x128(sp)
    c.ldsp         s0,0x120(sp)
    c.ldsp         s1,0x118(sp)
    c.ldsp         s2,0x110(sp)
    c.ldsp         s3,0x108(sp)
    c.ldsp         s4,0x100(sp)
    c.ldsp         s5,0xf8(sp)
    c.ldsp         s6,0xf0(sp)
    c.ldsp         s7,0xe8(sp)
    c.ldsp         s8,0xe0(sp)
    c.ldsp         s9,0xd8(sp)
    c.ldsp         s10,0xd0(sp)
    c.ldsp         s11,0xc8(sp)
    c.addi16sp     sp,0x130
    ret
19:
    c.mv           node_a,s9
    c.mv           context,s2
    jal            ra,acl_free_node
    c.j            17b
20:
    jal            ra,acl_dup_node
    c.mv           s8,context
    c.j            0b
21:
    c.lw           return_c,0x10(context)
    c.beqz         return_c,26f
    c.ld           level,0x60(node_a)
    c.ld           node_b,0x60(node_b)
    vsetvli        node_a,zero,e32,m1,ta,ma
    vmv.v.i        v2,0x0
    vmv.v.i        v4,0x2
    c.slli         return_c,0x20
    c.srli         return_c,0x20
    addi           node_b,node_b,0x40
    addi           level,level,0x40
22:
    vsetvli        a5,return_c,e32,m1,tu,mu
    vle32.v        v3,(level)
    vle32.v        v1,(node_b)
    slli           context,a5,0x2
    c.sub          return_c,a5
    c.add          node_b,context
    c.add          level,context
    vmslt.vv       v0,v1,v3
    vmsne.vv       v1,v1,v3
    vmerge.vim     v3,v4,0x1,v0
    vmv1r.v        v0,v1
    vor.vv         v2,v3,v2,v0.t
    c.bnez         return_c,22b
    vsetvli        node_a,zero,e32,m1,ta,ma
    vmv.s.x        v1,zero
    c.li           return_c,0x1
    vredor.vs      v2,v2,v1
    vmv.x.s        a5,v2
    bgeu           return_c,a5,26f
    c.li           return_c,0x2
    beq            a5,return_c,28f
    sd             zero,0x70(s11)
    c.mv           node_a,s11
    c.mv           context,s2
    jal            ra,acl_dup_node
    lw             level,0x10(s2)
    sd             context,0x0(s7)
    c.beqz         level,17b
    ld             a5,0x60(s9)
    c.ld           return_c,0x60(context)
    slli           node_b,level,0x20
    srli           level,node_b,0x1e
    add            node_a,level,a5
    addi           return_c,return_c,0x40
23:
    c.lw           level,0x40(a5)
    c.lw           node_b,0x0(return_c)
    bge            node_b,level,24f
    c.sw           level,0x0(return_c)
    c.lw           level,0x0(a5)
    sw             level,-0x40(return_c)
24:
    c.addi         a5,0x4
    c.addi         return_c,0x4
    bne            node_a,a5,23b
    c.j            17b
25:
    c.mv           node_a,s8
    c.mv           context,s2
    jal            ra,acl_free_node
    c.mv           s8,s9
    bne            s7,zero,15b
    c.j            16b
26:
    sd             s11,0x0(s7)
    c.j            17b
27:
    c.mv           node_a,s8
    c.mv           context,s2
    jal            ra,acl_free_node
    c.mv           s8,s11
    bne            s7,zero,15b
    c.j            16b
28:
   sd              s9,0x0(s7)
   c.j             17b
29:
    c.ldsp         context,0x8(sp)
    jal            ra,acl_free_node
    ld             level,0x40(s5)
    c.add          level,s11
    c.j            6b
.endm

TEST_CASE native_fail  flags=NATIVE_CSR

TEST_CASE patched_pass flags=PATCHED_CSR