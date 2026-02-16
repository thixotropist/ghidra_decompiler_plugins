---
title: Dangling Dependencies
weight: 20
description: PCodeOp transforms can create dangling - or 'free' dependencies, which throw exceptions later.
---

Functions like `vector_memcpy` use registers to hold temporaries like loop counters, source and destination pointers, and vector results.  Ghidra will likely propagate these via Phi node references.

The `whisper_sample_1` test case includes this example:

```text
Basic Block 0 0x000209be-0x000209cc
0x000209c8:e9:	u0x10000051(0x000209c8:e9) = (cast) a0(i)
0x000209c8:c:	u0x10000059(0x000209c8:c) = u0x10000051(0x000209c8:e9) + #0x10
0x000209c8:ea:	a0(0x000209c8:ea) = (cast) u0x10000059(0x000209c8:c)
0x000209ca:eb:	u0x10000061(0x000209ca:eb) = (cast) a0(i)
0x000209ca:f:	*(ram,u0x10000061(0x000209ca:eb)) = a0(0x000209c8:ea)
0x000209cc:10:	u0x00018480:1(0x000209cc:10) = a1(i) == #0x0
0x000209cc:11:	goto r0x00020a54:1(free) if (u0x00018480:1(0x000209cc:10) != 0)
Basic Block 1 0x00020a54-0x00020a60
0x00020a5c:77:	call ffunc_0x0001f950(free)(#0xfa298)
0x00020a60:78:	return(#0x1:4)
Basic Block 2 0x000209ce-0x000209d0
0x000209ce:13:	a3(0x000209ce:13) = #0x0
0x000209d0:e5:	u0x10000031(0x000209d0:e5) = a3(0x000209ce:13)
0x000209d0:e7:	u0x10000041(0x000209d0:e7) = a1(i)
Basic Block 3 0x000209d2-0x000209e8
0x000209d2:b7:	a5(0x000209d2:b7) = u0x10000041(0x000209d0:e7) ? a5(0x000209d6:16)
0x000209d2:ae:	a3(0x000209d2:ae) = u0x10000031(0x000209d0:e5) ? u0x10000039(0x000209e8:e6)
0x000209d2:15:	a2(0x000209d2:15) = vsetvli_e8m1tama(#0x0)
0x000209d6:16:	a5(0x000209d6:16) = a5(0x000209d2:b7) + a3(0x000209d2:ae)(*#0x1)
0x000209d8:18:	v1(0x000209d8:18) = vle8ff_v(a5(0x000209d6:16))
0x000209dc:1a:	v1(0x000209dc:1a) = vmseq_vi(v1(0x000209d8:18),#0x0)
0x000209e4:20:	a6(0x000209e4:20) = vfirst_m(v1(0x000209dc:1a))
0x000209e8:21:	u0x00001f80:1(0x000209e8:21) = a6(0x000209e4:20) < #0x0
0x000209e8:e6:	u0x10000039(0x000209e8:e6) = vl(i)
0x000209e8:22:	goto r0x000209d2:1(free) if (u0x00001f80:1(0x000209e8:21) != 0)
Basic Block 4 0x000209ec-0x000209f2
0x000209ee:ec:	u0x10000069(0x000209ee:ec) = (cast) a1(i)
0x000209ee:e1:	u0x10000011(0x000209ee:e1) = a6(0x000209e4:20) - u0x10000069(0x000209ee:ec)
0x000209ee:24:	a5(0x000209ee:24) = a5(0x000209d6:16) + u0x10000011(0x000209ee:e1)(*#0x1)
0x000209f2:27:	u0x00002000:1(0x000209f2:27) = a5(0x000209ee:24) < #0x10
0x000209f2:e8:	u0x10000049(0x000209f2:e8) = a5(0x000209ee:24)
0x000209f2:28:	goto r0x00020a18:1(free) if (u0x00002000:1(0x000209f2:27) == 0)
Basic Block 5 0x00020a18-0x00020a3a
0x00020a18:57:	a0(0x00020a18:57) = a5(0x000209ee:24) + #0x1(*#0x1)
0x00020a28:62:	u0x10000071(0x00020a28:62) = call ffunc_0x0001fad0(free)(a0(0x00020a18:57),a2(0x000209d2:15))
0x00020a28:ed:	a0(0x00020a28:ed) = (cast) u0x10000071(0x00020a28:62)
0x00020a38:ee:	u0x10000079(0x00020a38:ee) = (cast) a0(i)
0x00020a38:6e:	*(ram,u0x10000079(0x00020a38:ee)) = a0(0x00020a28:ed)
0x00020a3a:ef:	u0x10000081(0x00020a3a:ef) = (cast) a0(i)
0x00020a3a:70:	u0x10000089(0x00020a3a:70) = u0x10000081(0x00020a3a:ef) + #0x10
0x00020a3a:f0:	u0x00019180(0x00020a3a:f0) = (cast) u0x10000089(0x00020a3a:70)
0x00020a3a:71:	*(ram,u0x00019180(0x00020a3a:f0)) = a5(0x000209ee:24)
Basic Block 6 0x000209f6-0x000209f8
0x000209f8:2b:	u0x00001e00:1(0x000209f8:2b) = a5(0x000209ee:24) == #0x1
0x000209f8:2c:	goto r0x00020a10:1(free) if (u0x00001e00:1(0x000209f8:2b) != 0)
Basic Block 7 0x00020a10-0x00020a16
0x00020a10:50:	u0x00046000:1(0x00020a10:50) = *(ram,a1(i))
0x00020a12:f1:	u0x10000091(0x00020a12:f1) = (cast) a0(i)
0x00020a12:53:	u0x10000099(0x00020a12:53) = u0x10000091(0x00020a12:f1) + #0x10
0x00020a12:f2:	u0x00003500(0x00020a12:f2) = (cast) u0x10000099(0x00020a12:53)
0x00020a12:54:	*(ram,u0x00003500(0x00020a12:f2)) = u0x00046000:1(0x00020a10:50)
0x00020a16:55:	goto r0x000209fe:1(free)
Basic Block 8 0x000209fc-0x000209fc
0x000209fc:2d:	u0x00018500:1(0x000209fc:2d) = a5(0x000209ee:24) == #0x0
0x000209fc:2e:	goto r0x00020a3c:1(free) if (u0x00018500:1(0x000209fc:2d) == 0)
Basic Block 9 0x00020a3e-0x00020a50
0x00020a3e:a4:	a2(0x00020a3e:a4) = u0x10000019(0x00020a50:e2) ? u0x10000049(0x000209f2:e8) ? u0x10000049(0x000209f2:e8)
0x00020a3e:9f:	a1(0x00020a3e:9f) = a1(0x00020a48:47) ? a1(i) ? a1(i)
0x00020a3e:9a:	a0(0x00020a3e:9a) = a0(0x00020a4e:f4) ? a0(0x000209c8:ea) ? a0(0x00020a28:ed)
0x00020a3e:43:	a3(0x00020a3e:43) = vsetvli_e8m1tama(a2(0x00020a3e:a4))
0x00020a42:45:	v1(0x00020a42:45) = vle8_v(a1(0x00020a3e:9f))
0x00020a46:cb:	u0x10000008(0x00020a46:cb) = - a3(0x00020a3e:43)
0x00020a46:46:	a2(0x00020a46:46) = a2(0x00020a3e:a4) + u0x10000008(0x00020a46:cb)(*#0x1)
0x00020a48:47:	a1(0x00020a48:47) = a1(0x00020a3e:9f) + a3(0x00020a3e:43)(*#0x1)
0x00020a4a:49:	vse8_v(v1(0x00020a42:45),a0(0x00020a3e:9a))
0x00020a4e:f3:	u0x100000a1(0x00020a4e:f3) = (cast) a0(0x00020a3e:9a)
0x00020a4e:4a:	u0x100000a9(0x00020a4e:4a) = u0x100000a1(0x00020a4e:f3) + a3(0x00020a3e:43)
0x00020a4e:f4:	a0(0x00020a4e:f4) = (cast) u0x100000a9(0x00020a4e:4a)
0x00020a50:4b:	u0x00018500:1(0x00020a50:4b) = a2(0x00020a46:46) != #0x0
0x00020a50:e2:	u0x10000019(0x00020a50:e2) = a2(0x00020a46:46)
0x00020a50:4c:	goto r0x00020a3e:1(free) if (u0x00018500:1(0x00020a50:4b) != 0)
Basic Block 10 0x000209fe-0x00020a0e
0x000209fe:9b:	a0(0x000209fe:9b) = a0(0x000209c8:ea) ? a0(0x000209c8:ea) ? a0(0x00020a4e:f4)
0x000209fe:31:	a3(0x000209fe:31) = *(ram,a0(i))
0x00020a00:f5:	u0x100000b1(0x00020a00:f5) = (cast) a0(i)
0x00020a00:33:	u0x100000b9(0x00020a00:33) = u0x100000b1(0x00020a00:f5) + #0x8
0x00020a00:f6:	u0x00019180(0x00020a00:f6) = (cast) u0x100000b9(0x00020a00:33)
0x00020a00:34:	*(ram,u0x00019180(0x00020a00:f6)) = a5(0x000209ee:24)
0x00020a02:35:	a5(0x00020a02:35) = a5(0x000209ee:24) + a3(0x000209fe:31)(*#0x1)
0x00020a04:38:	*(ram,a5(0x00020a02:35)) = #0x0:1
0x00020a0e:41:	return(#0x0) a0(0x000209fe:9b)
```

We have this dependency to resolve:

```text
0x000209fe:9b: a0(0x000209fe:9b) = a0(0x000209c8:ea) ? a0(0x000209c8:ea) ? a0(0x00020a4e:f4)
```

The desired transform result is something like:

```text
0x00020a3e:a4:	a2(0x00020a3e:a4) = u0x10000049(0x000209f2:e8) ? u0x10000049(0x000209f2:e8)
0x00020a3e:9f:	a1(0x00020a3e:9f) = a1(i) ? a1(i)
0x00020a3e:9a:	a0(0x00020a3e:9a) = a0(0x000209c8:ea) ? a0(0x00020a28:ed)
0x00020a3e:43:	vector_memcpy(a0(0x00020a3e:9a), a1(0x00020a3e:9f), a2(0x00020a3e:a4))
0x00020a3e:*:   a0(0x00020a3e:*) = a0(0x00020a3e:9a) + a2(0x00020a3e:a4)
...
0x000209fe:9b: a0(0x000209fe:9b) = a0(0x000209c8:ea) ? a0(0x000209c8:ea) ? a0(0x00020a3e:*)
```

The logic steps are:

1. remove loop variable input varnodes from the three Phi nodes at the top of the loop
2. complete the `vector_memcpy` transform
3. delete all non-phi node pcodeops from the loop
4. insert a new addition pcodeop to correct the value of a0
5. replace all references to `a0(0x00020a3e:9a)` with `a0(0x00020a3e:*)`

An alternate, and simpler, transform would simply remove the exterior dependency from any Phi nodes
outside the loop.  This assumes that the temporary registers used by GCC's builtin_memcpy primitive
are never exposed to downstream code.

Let's try an intermediate sequence first.

If `dependentVarnodesOutsideLoop` is not empty call a new function to fix dependencies *before*
the transform is begun.  This will allow for multiple experimental dependency removal strategies,
and return a failure code if none of them are feasible.

The simplest dependency fix is to remove loop varnodes from descendent ops.  If we do that we currently get
loop blocks like:

```text
Basic Block 9 0x00020a3e-0x00020a50
0x00020a3e:a4:  a2(0x00020a3e:a4) = a5(0x000209ee:24) ? a5(0x000209ee:24)
0x00020a3e:9f:  a1(0x00020a3e:9f) = a1(i) ? a1(i)
0x00020a3e:9a:  a0(0x00020a3e:9a) = a0(0x000209c8:c) ? a0(0x00020a28:62)
0x00020a3e:e2:  vector_memcpy(a0(0x00020a3e:9a),a1(0x00020a3e:9f),a2(0x00020a3e:a4))
```

The reconstructed C code looks awkward - perhaps we can clear it up?  For instance,
if we have a Phi node matching A = Y ? Y then replace descendent references to A with Y and delete the Phi node.
