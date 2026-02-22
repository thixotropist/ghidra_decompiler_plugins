/**
 * @file design_docs.hh
 * @page design_notes Design Notes
 * @section exemplar_pcode PCode Exemplars
 *
 * We will use two relatively simple examples for this design study - RISC-V stdlib vectorizations
 * of `memcpy` and `strlen`.
 *
 * @subsection memcpy_exemplar memcpy
 *
 * The `vector_memcpy` pcode is:
 * @verbatim
0x00020a3e:df:  c0x0c20(0x00020a3e:df) = c0x0c20(0x00020a3e:df) ? c0x0c20(i) ? c0x0c20(0x00020a28:c5)
0x00020a3e:a2:  a2(0x00020a3e:a2) = a2(0x00020a46:42) ? a5(0x000209ee:20) ? a5(0x000209ee:20)
0x00020a3e:9d:  a1(0x00020a3e:9d) = a1(0x00020a48:43) ? a1(i) ? a1(i)
0x00020a3e:98:  a0(0x00020a3e:98) = a0(0x00020a4e:46) ? a0(0x000209c8:c) ? a0(0x00020a28:5e)
0x00020a3e:3f:  a3(0x00020a3e:3f) = vsetvli_e8m1tama(a2(0x00020a3e:a2))
0x00020a42:41:  v1(0x00020a42:41) = vle8_v(a1(0x00020a3e:9d))
0x00020a46:c3:  u0x1000001a(0x00020a46:c3) = a3(0x00020a3e:3f) * #0xffffffffffffffff
0x00020a46:42:  a2(0x00020a46:42) = a2(0x00020a3e:a2) + u0x1000001a(0x00020a46:c3)(*#0x1)
0x00020a48:43:  a1(0x00020a48:43) = a1(0x00020a3e:9d) + a3(0x00020a3e:3f)(*#0x1)
0x00020a4a:45:  vse8_v(v1(0x00020a42:41),a0(0x00020a3e:98))
0x00020a4e:46:  a0(0x00020a4e:46) = a0(0x00020a3e:98) + a3(0x00020a3e:3f)
0x00020a50:47:  u0x00017b80:1(0x00020a50:47) = a2(0x00020a46:42) != #0x0
0x00020a50:48:  goto Block_9:0x00020a3e if (u0x00017b80:1(0x00020a50:47) != 0) else Block_10:0x000209fe
@endverbatim

* @subsection strlen_exemplar strlen
* @verbatim
Basic Block 2 0x000209ce-0x000209d0
0x000209ce:13:	a3(0x000209ce:13) = #0x0
0x000209d0:e2:	u0x1000002b(0x000209d0:e2) = a3(0x000209ce:13)
0x000209d0:e4:	u0x1000003b(0x000209d0:e4) = a1(i)
Basic Block 3 0x000209d2-0x000209e8
0x000209d2:b5:	a5(0x000209d2:b5) = u0x1000003b(0x000209d0:e4) ? a5(0x000209d6:16)
0x000209d2:ac:	a3(0x000209d2:ac) = u0x1000002b(0x000209d0:e2) ? u0x10000033(0x000209e8:e3)
0x000209d2:15:	a2(0x000209d2:15) = vsetvli_e8m1tama(#0x0)
0x000209d6:16:	a5(0x000209d6:16) = a5(0x000209d2:b5) + a3(0x000209d2:ac)(*#0x1)
0x000209d8:18:	v1(0x000209d8:18) = vle8ff_v(a5(0x000209d6:16))
0x000209dc:1a:	v1(0x000209dc:1a) = vmseq_vi(v1(0x000209d8:18),#0x0)
0x000209e4:1c:	a6(0x000209e4:1c) = vfirst_m(v1(0x000209dc:1a))
0x000209e8:1d:	u0x00002080:1(0x000209e8:1d) = a6(0x000209e4:1c) < #0x0
0x000209e8:e3:	u0x10000033(0x000209e8:e3) = c0x0c20(i)
0x000209e8:1e:	goto Block_3:0x000209d2 if (u0x00002080:1(0x000209e8:1d) != 0) else Block_4:0x000209ec
Basic Block 4 0x000209ec-0x000209f2
0x000209ee:e7:	u0x10000053(0x000209ee:e7) = (cast) a1(i)
0x000209ee:e0:	u0x10000023(0x000209ee:e0) = a6(0x000209e4:1c) - u0x10000053(0x000209ee:e7)
0x000209ee:20:	a5(0x000209ee:20) = a5(0x000209d6:16) + u0x10000023(0x000209ee:e0)(*#0x1)
@endverbatim

 * @section loop_models Loop Modeling
 *
 * We need to do a better job of feature extraction and transformation of loops
 * involving vector instructions.  We started with code that recognizes and transforms
 * the simplest `vector_memcpy` patterns, and now want to add more complex standard
 * functions like `vector_strlen`, `vector_strcmp`, and their variants.
 *
 * What are the most common components of these loops?  Can we provide shared code
 * for those components to minimize the amount of ad hoc code needed for each
 * vector transformation?
 *
 * This design study will start with the `vector_memcpy` patterns and code and then:
 * - itemize features in common with `vector_strlen`
 * - implement common supporting code in or near VectorLoop::collect_common_elements
 * - remove ad hoc code from VectorMatcher::transformMemcpy and
 *   VectorMatcher::collect_loop_registers
 * - verify no regressions when running integration tests.
 *
 * @subsection loop_structure Loop Structure
 * A vectorized loop takes up a single Ghidra block.  There may be prolog code
 * in the preceding block, to set up registers and pointers.  And there may be
 * epilog code in the following block to transform the result into a desired value.
 * Within the loop block itself there may be:
 * - one or more `PHI` or `MULTIEQUAL` codes showing the dependency chain of Varnodes.  These codes
 *   define the interface between registers that change within the loop and the code locations
 *   that set the initial values of those registers upstream of the loop.
 * - one or more vector load instructions.
 * - vector operations to transform the loaded values.  These may apply to either source operands
 *   or pointer arrays.
 * - zero or more vector store instructions.  Many loops are reduction loops, with one or more source
 *   vectors reduced down to a scalar result.
 * - pointer and counter updates
 * - conditional tests to detect the end of the loop
 * @note Compilers sometimes vectorize loops into multiple paths, where one path handles however many
 * elements fit within a single vector register and the another path handles remaining elements.
 *
 * @subsection loop_models_sources Source Vectors are Common
 *
 * Both `vector_memcpy` and `vector_strlen` operate on source vectors.  `vector_strcmp`
 * adds a second source vector, and `vector_memcpy` adds a destination vector with
 * some common features.  This suggests we need the `VectorOperand` class to model common
 * features and code.  There exists some supporting but unused code already, so adapt that
 * and discard the unneeded support for striped vector operands.
 *
 * The simplest test case for this exercise is `test/whisper_sample_1.ghidra`, as it contains one
 * sample each of `vector_memcpy` and `vector_strlen`.

* There are two VectorOperands in use within @ref memcpy_exemplar
*
* Vector source:
* - `base = a1(i)`
* - `opType = load`
* - `vector_varnode = v1(0x00020a42:41)`
* - `pointer_varnode = a1(0x00020a3e:9d)`
* - `element_length =  1 byte`
* - `incrementOps = +=a3`
*
* Vector destination:
* - `base = a0(0x00020a3e:98)`
* - `opType = store`
* - `vector_varnode = v1(0x00020a42:41)`
* - `pointer_varnode = a0(0x00020a3e:98)`
* - `element_length = 1 byte`
* - `incrementOps = +=a3`

* This vector sequence should be transformed into `vector_memcpy(a0(0x00020a3e:98, a1(i), a5(0x000209ee:20))`.

* A single VectorOperand is used in @ref strlen_exemplar
*  Vector source:
* - `base = a1(i)`
* - `opType = load`
* - `vector_varnode = v1(0x000209d8:18)`
* - `pointer_varnode = a5(0x000209d6:16)`
* - `element_length = 1 byte`
* - `incrementOps = +=a3`
*
* This vector sequence should be transformed into `a5(0x000209ee:20) = vector_strlen(a1(i))`.
*
* @subsection loop_data Loop Data
*
* The `VectorMatcher` object and its member component `VectorLoop` object hold common data used to
* recognize - and potentially transform - vector instruction sequences found in and near
* a loop.  Key data include:
* - `VectorMatcher::externalDependentOps` lists all PCodeOps external to the loop but dependent
*   on Varnodes produced within the loop.  These include results from the loop as well as temporary
*   registers that need to be deleted.
*
* @subsection loop_transforms Loop Transforms
*
* Vector loop features are next matched against common patterns, then a single potential transform
* is selected.  The following steps include:
* - use the extracted common features to locate prolog, epilog, result registers, and temporary registers.
* - if any temporary registers have been marked as parameters to subsequent function calls, abort the transform.
*   The transform may be reattempted if that subsequent function call signature is trimmed to remove the assumed
*   dependency.\
* - resolve the linkages between loop-internal temporary registers and their external registers.  This
*   usually gives the parameters to the transform code.
* - delete all PcodeOps within the loop, replacing them with the transform `vector_*` function call.
* - edit the function's BlockGraph structure to remove the enclosing `do ... while` control block.
* - make a cleanup pass through the prolog, loop block, and epilog block to remove any PCodeOps with
*   unused output Varnodes.
*/