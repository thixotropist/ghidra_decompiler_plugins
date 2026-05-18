---
title: Transforms
weight: 10
description: A very simple loop transform into `vector_memcpy`
---

A vector_memcpy loop can look like this:

```text
Basic Block 1 0x00000048-0x0000005a
0x00000048:e:	a2(0x00000048:e) = a2(0x00000050:3) ? a2(i)
0x00000048:d:	a1(0x00000048:d) = a1(0x00000058:15) ? a1(i)
0x00000048:c:	a0(0x00000048:c) = a0(0x00000052:13) ? a0(i)
0x00000048:0:	a3(0x00000048:0) = vsetvli_e8m1tama(a2(0x00000048:e))
0x0000004c:2:	v1(0x0000004c:2) = vle8_v(a1(0x00000048:d))
0x00000050:3:	a2(0x00000050:3) = a2(0x00000048:e) - a3(0x00000048:0)
0x00000052:12:	u0x10000008(0x00000052:12) = (cast) a0(0x00000048:c)
0x00000052:4:	u0x10000010(0x00000052:4) = u0x10000008(0x00000052:12) + a3(0x00000048:0)
0x00000052:13:	a0(0x00000052:13) = (cast) u0x10000010(0x00000052:4)
0x00000054:6:	vse8_v(v1(0x0000004c:2),a0(0x00000052:13))
0x00000058:14:	u0x10000018(0x00000058:14) = (cast) a1(0x00000048:d)
0x00000058:7:	u0x10000020(0x00000058:7) = u0x10000018(0x00000058:14) + a3(0x00000048:0)
0x00000058:15:	a1(0x00000058:15) = (cast) u0x10000020(0x00000058:7)
0x0000005a:8:	u0x00018500:1(0x0000005a:8) = a2(0x00000050:3) != #0x0
0x0000005a:9:	goto r0x00000048:1(free) if (u0x00018500:1(0x0000005a:8) != 0)
Basic Block 2 0x0000005c-0x0000005c
0x0000005c:a:	return(#0x0)
```

A transform should turn this into something like:

```text
Basic Block 1 0x00000048-0x0000005c
0x00000048:e:	a2(0x00000048:e) = a2(i)
0x00000048:d:	a1(0x00000048:d) = a1(i)
0x00000048:c:	a0(0x00000048:c) = a0(i)
0x00000048:0:	vector_memset(a0(0x00000048:c),a1(0x00000048:e),a2(0x00000048:d))
0x00000048:*:   a0(0x00000048:c) = a0(0x00000048:c) + a2(0x00000048:e)
0x00000048:*:   a1(0x00000048:d) = a1(0x00000048:d) + a2(0x00000048:e)
0x00000048:*:   a2(0x00000048:e) = 0
0x00000048:*:   a3(0x00000048:*) = 0
0x0000005c:a:	return(#0x0)
```

The transform transaction should be:

* remove interior varnodes from Phi nodes, reducing the number of slots by one - three times
* identify destination, source, and number of elements varnodes
* convert number of elements to number of bytes
* generate the vector_memcpy opcode
* scan the function for Phi nodes referencing any of the interior pcodes, replacing the
  Phi node varnodes with references to the new varnodes inserted after the vector_memset
* delete all pcodeops in the block
* merge blocks
