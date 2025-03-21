# collect vector sequences we would like to see transformed into builtin_memcpy calls
# source:  whisper.cpp built with O3, fast-math, and r64gcv


.section .text

# copy fixed 2 bytes
.extern memcpy_i2
memcpy_i2:
    vsetivli zero,0x2,e8,mf8,ta,ma 
    vle8.v   v1,(a1)
    vse8.v   v1,(a0)
    ret

# copy fixed 4 bytes
.extern memcpy_i4
memcpy_i4:
    vsetivli  zero,0x4,e8,mf4,ta,ma 
    nop
    nop
    vle8.v    v1,(a1)
    nop
    vse8.v    v1,(a0)
    ret

# copy fixed 8 bytes
.extern memcpy_i8
memcpy_i8:
    vsetivli  zero,0x8,e8,mf2,ta,ma 
    nop
    nop
    vle8.v    v1,(a1)
    nop
    vse8.v    v1,(a0)
    ret

# copy fixed 15 bytes
.extern memcpy_i15
memcpy_i15:
    vsetivli zero,0xf,e8,m1,ta,ma  
    vle8.v   v1,(a1)
    nop
    nop
    vse8.v   v1,(a0)
    ret

# copy variable
.extern memcpy_v1
memcpy_v1:
    vsetvli  a3,a2,e8,m1,ta,ma
    vle8.v   v1,(a1)
    sub      a2,a2,a3
    c.add    a0,a3
    vse8.v   v1,(a0)
    c.add    a1,a3
    bne      a2,zero,memcpy_v1
    ret
