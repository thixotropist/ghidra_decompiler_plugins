/**
 * @file user_pcode.cc
 * @brief Model RISC-V ISA extensions
 */

#include <string>
#include <vector>
#include <map>
#include <utility>

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/type.hh"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh"

#include "user_pcode.hh"

namespace riscv_vector
{

///@brief Vector setup instructions
static const std::string vector_setup[] =
{
    "vsetvl", "vsetvli", "vsetvli_e8m1tumu", "vsetvli_e8m2tumu",
    "vsetvli_e8m4tumu", "vsetvli_e8m8tumu", "vsetvli_e8mf8tumu",
    "vsetvli_e8mf4tumu", "vsetvli_e8mf2tumu", "vsetvli_e16m1tumu",
    "vsetvli_e16m2tumu", "vsetvli_e16m4tumu", "vsetvli_e16m8tumu",
    "vsetvli_e16mf8tumu", "vsetvli_e16mf4tumu",
    "vsetvli_e16mf2tumu", "vsetvli_e32m1tumu", "vsetvli_e32m2tumu",
    "vsetvli_e32m4tumu", "vsetvli_e32m8tumu", "vsetvli_e32mf8tumu",
    "vsetvli_e32mf4tumu", "vsetvli_e32mf2tumu", "vsetvli_e64m1tumu",
    "vsetvli_e64m2tumu", "vsetvli_e64m4tumu", "vsetvli_e64m8tumu",
    "vsetvli_e64mf8tumu", "vsetvli_e64mf4tumu",
    "vsetvli_e64mf2tumu", "vsetvli_e8m1tamu", "vsetvli_e8m2tamu",
    "vsetvli_e8m4tamu", "vsetvli_e8m8tamu", "vsetvli_e8mf8tamu",
    "vsetvli_e8mf4tamu", "vsetvli_e8mf2tamu", "vsetvli_e16m1tamu",
    "vsetvli_e16m2tamu", "vsetvli_e16m4tamu", "vsetvli_e16m8tamu",
    "vsetvli_e16mf8tamu", "vsetvli_e16mf4tamu", "vsetvli_e16mf2tamu",
    "vsetvli_e32m1tamu", "vsetvli_e32m2tamu", "vsetvli_e32m4tamu",
    "vsetvli_e32m8tamu", "vsetvli_e32mf8tamu", "vsetvli_e32mf4tamu",
    "vsetvli_e32mf2tamu", "vsetvli_e64m1tamu", "vsetvli_e64m2tamu",
    "vsetvli_e64m4tamu", "vsetvli_e64m8tamu", "vsetvli_e64mf8tamu",
    "vsetvli_e64mf4tamu", "vsetvli_e64mf2tamu", "vsetvli_e8m1tuma",
    "vsetvli_e8m2tuma", "vsetvli_e8m4tuma", "vsetvli_e8m8tuma",
    "vsetvli_e8mf8tuma", "vsetvli_e8mf4tuma", "vsetvli_e8mf2tuma",
    "vsetvli_e16m1tuma", "vsetvli_e16m2tuma", "vsetvli_e16m4tuma",
    "vsetvli_e16m8tuma", "vsetvli_e16mf8tuma", "vsetvli_e16mf4tuma",
    "vsetvli_e16mf2tuma", "vsetvli_e32m1tuma", "vsetvli_e32m2tuma",
    "vsetvli_e32m4tuma", "vsetvli_e32m8tuma", "vsetvli_e32mf8tuma",
    "vsetvli_e32mf4tuma", "vsetvli_e32mf2tuma", "vsetvli_e64m1tuma",
    "vsetvli_e64m2tuma", "vsetvli_e64m4tuma", "vsetvli_e64m8tuma",
    "vsetvli_e64mf8tuma", "vsetvli_e64mf4tuma", "vsetvli_e64mf2tuma",
    "vsetvli_e8m1tama", "vsetvli_e8m2tama", "vsetvli_e8m4tama",
    "vsetvli_e8m8tama", "vsetvli_e8mf8tama", "vsetvli_e8mf4tama",
    "vsetvli_e8mf2tama", "vsetvli_e16m1tama", "vsetvli_e16m2tama",
    "vsetvli_e16m4tama", "vsetvli_e16m8tama", "vsetvli_e16mf8tama",
    "vsetvli_e16mf4tama", "vsetvli_e16mf2tama", "vsetvli_e32m1tama",
    "vsetvli_e32m2tama", "vsetvli_e32m4tama", "vsetvli_e32m8tama",
    "vsetvli_e32mf8tama", "vsetvli_e32mf4tama", "vsetvli_e32mf2tama",
    "vsetvli_e64m1tama", "vsetvli_e64m2tama", "vsetvli_e64m4tama",
    "vsetvli_e64m8tama", "vsetvli_e64mf8tama", "vsetvli_e64mf4tama",
    "vsetvli_e64mf2tama", "vsetivli", "vsetivli_e8m1tumu",
    "vsetivli_e8m2tumu", "vsetivli_e8m4tumu", "vsetivli_e8m8tumu",
    "vsetivli_e8mf8tumu", "vsetivli_e8mf4tumu", "vsetivli_e8mf2tumu",
    "vsetivli_e16m1tumu", "vsetivli_e16m2tumu", "vsetivli_e16m4tumu",
    "vsetivli_e16m8tumu", "vsetivli_e16mf8tumu", "vsetivli_e16mf4tumu",
    "vsetivli_e16mf2tumu", "vsetivli_e32m1tumu", "vsetivli_e32m2tumu",
    "vsetivli_e32m4tumu", "vsetivli_e32m8tumu", "vsetivli_e32mf8tumu",
    "vsetivli_e32mf4tumu", "vsetivli_e32mf2tumu", "vsetivli_e64m1tumu",
    "vsetivli_e64m2tumu", "vsetivli_e64m4tumu", "vsetivli_e64m8tumu",
    "vsetivli_e64mf8tumu", "vsetivli_e64mf4tumu",
    "vsetivli_e64mf2tumu", "vsetivli_e8m1tamu", "vsetivli_e8m2tamu",
    "vsetivli_e8m4tamu", "vsetivli_e8m8tamu", "vsetivli_e8mf8tamu",
    "vsetivli_e8mf4tamu", "vsetivli_e8mf2tamu", "vsetivli_e16m1tamu",
    "vsetivli_e16m2tamu", "vsetivli_e16m4tamu", "vsetivli_e16m8tamu",
    "vsetivli_e16mf8tamu", "vsetivli_e16mf4tamu",
    "vsetivli_e16mf2tamu", "vsetivli_e32m1tamu", "vsetivli_e32m2tamu",
    "vsetivli_e32m4tamu", "vsetivli_e32m8tamu", "vsetivli_e32mf8tamu",
    "vsetivli_e32mf4tamu", "vsetivli_e32mf2tamu", "vsetivli_e64m1tamu",
    "vsetivli_e64m2tamu", "vsetivli_e64m4tamu", "vsetivli_e64m8tamu",
    "vsetivli_e64mf8tamu", "vsetivli_e64mf4tamu",
    "vsetivli_e64mf2tamu", "vsetivli_e8m1tuma", "vsetivli_e8m2tuma",
    "vsetivli_e8m4tuma", "vsetivli_e8m8tuma", "vsetivli_e8mf8tuma",
    "vsetivli_e8mf4tuma", "vsetivli_e8mf2tuma", "vsetivli_e16m1tuma",
    "vsetivli_e16m2tuma", "vsetivli_e16m4tuma", "vsetivli_e16m8tuma",
    "vsetivli_e16mf8tuma", "vsetivli_e16mf4tuma", "vsetivli_e16mf2tuma",
    "vsetivli_e32m1tuma", "vsetivli_e32m2tuma", "vsetivli_e32m4tuma",
    "vsetivli_e32m8tuma", "vsetivli_e32mf8tuma", "vsetivli_e32mf4tuma",
    "vsetivli_e32mf2tuma", "vsetivli_e64m1tuma", "vsetivli_e64m2tuma",
    "vsetivli_e64m4tuma", "vsetivli_e64m8tuma", "vsetivli_e64mf8tuma",
    "vsetivli_e64mf4tuma", "vsetivli_e64mf2tuma", "vsetivli_e8m1tama",
    "vsetivli_e8m2tama", "vsetivli_e8m4tama", "vsetivli_e8m8tama",
    "vsetivli_e8mf8tama", "vsetivli_e8mf4tama", "vsetivli_e8mf2tama",
    "vsetivli_e16m1tama", "vsetivli_e16m2tama", "vsetivli_e16m4tama",
    "vsetivli_e16m8tama", "vsetivli_e16mf8tama", "vsetivli_e16mf4tama",
    "vsetivli_e16mf2tama", "vsetivli_e32m1tama", "vsetivli_e32m2tama",
    "vsetivli_e32m4tama", "vsetivli_e32m8tama", "vsetivli_e32mf8tama",
    "vsetivli_e32mf4tama", "vsetivli_e32mf2tama", "vsetivli_e64m1tama",
    "vsetivli_e64m2tama", "vsetivli_e64m4tama", "vsetivli_e64m8tama",
    "vsetivli_e64mf8tama", "vsetivli_e64mf4tama", "vsetivli_e64mf2tama",
};
///@brief Basic vector loads defined in Section 7.4 of risc-v-spec-1.0
static const std::string vector_unit_stride_loads[] =
{
    "vle8_v", "vle16_v", "vle32_v", "vle64_v"
};

///@brief Basic vector stores defined in Section 7.4 of risc-v-spec-1.0
static const std::string vector_unit_stride_stores[] =
{
    "vse8_v", "vse16_v", "vse32_v", "vse64_v"
};
///@brief Vector mask loads defined in Section 7.4 of risc-v-spec-1.0
static const std::string vector_unit_stride_mask_loads[] =
{
    "vlm_v"
};
///@brief Vector mask stores defined in Section 7.4 of risc-v-spec-1.0
static const std::string vector_unit_stride_mask_stores[] =
{
    "vsm_v"
};
///@brief Strided vector loads defined in Section 7.5 of risc-v-spec-1.0
static const std::string vector_strided_loads[] =
{
    "vlse8_v", "vlse16_v", "vlse32_v", "vlse64_v"
};
///@brief Strided vector stores defined in Section 7.5 of risc-v-spec-1.0
static const std::string vector_strided_stores[] =
{
    "vsse8_v", "vsse16_v", "vsse32_v", "vsse64_v"
};
///@brief Strided indexed unordered loads defined in Section 7.6 of risc-v-spec-1.0
static const std::string vector_strided_indexed_unordered_loads[] =
{
    "vluxei8_v", "vluxei16_v", "vluxei32_v", "vluxei64_v"
};
///@brief Strided indexed ordered loads defined in Section 7.6 of risc-v-spec-1.0
static const std::string vector_strided_indexed_ordered_loads[] =
{
    "vloxei8_v", "vloxei16_v", "vloxei32_v", "vloxei64_v"
};
///@brief Strided indexed unordered stores defined in Section 7.6 of risc-v-spec-1.0
static const std::string vector_strided_indexed_unordered_stores[] =
{
    "vsuxei8_v", "vsuxei16_v", "vsuxei32_v", "vsuxei64_v"
};
///@brief Strided indexed ordered stores defined in Section 7.6 of risc-v-spec-1.0
static const std::string vector_strided_indexed_ordered_stores[] =
{
    "vsoxei8_v", "vsoxei16_v", "vsoxei32_v", "vsoxei64_v"
};
///@brief Fault-only-first loads defined in Section 7.7 of risc-v-spec-1.0
static const std::string vector_fault_only_first_loads[] =
{
    "vle8ff_v", "vle16ff_v", "vle32ff_v", "vle64ff_v"
};
///@todo consider splitting instructions like "vlseg2se8_v" into a separate group
///@brief Vector unit stride segmented loads in Section 7.8.1 of risc-v-spec-1.0
///@details instructions like `vlseg<nf>e<eew>.v vd, (rs1), vm` or `vsseg<nf>e<eew>.v vs3, (rs1), vm`
static const std::string vector_segmented_loads[] =
{
    "vlseg2e16_v", "vlseg3e16_v", "vlseg4e16_v", "vlseg5e16_v",
    "vlseg6e16_v", "vlseg7e16_v", "vlseg8e16_v", "vlseg2e32_v",
    "vlseg3e32_v", "vlseg4e32_v", "vlseg5e32_v", "vlseg6e32_v",
    "vlseg7e32_v", "vlseg8e32_v", "vlseg2e64_v", "vlseg3e64_v",
    "vlseg4e64_v", "vlseg5e64_v", "vlseg6e64_v", "vlseg7e64_v",
    "vlseg8e64_v", "vlseg2e8_v", "vlseg3e8_v", "vlseg4e8_v",
    "vlseg5e8_v", "vlseg6e8_v", "vlseg7e8_v", "vlseg8e8_v",
    "vlseg2se8_v", "vlseg3se8_v", "vlseg4se8_v", "vlseg5se8_v",
    "vlseg6se8_v", "vlseg7se8_v", "vlseg8se8_v",
};

///@brief Vector unit stride fault-only-first segmented loads in Section 7.8.1 of risc-v-spec-1.0
///@details instructions like `vlseg<nf>e<eew>ff.v vd, (rs1), vm` or `vsseg<nf>e<eew>.v vs3, (rs1), vm`
static const std::string vector_segmented_fault_only_first_loads[] =
{
    "vlseg2e16ff_v", "vlseg3e16ff_v", "vlseg4e16ff_v", "vlseg5e16ff_v",
    "vlseg6e16ff_v", "vlseg7e16ff_v", "vlseg8e16ff_v", "vlseg2e32ff_v",
    "vlseg3e32ff_v", "vlseg4e32ff_v", "vlseg5e32ff_v", "vlseg6e32ff_v",
    "vlseg7e32ff_v", "vlseg8e32ff_v", "vlseg2e64ff_v", "vlseg3e64ff_v",
    "vlseg4e64ff_v", "vlseg5e64ff_v", "vlseg6e64ff_v", "vlseg7e64ff_v",
    "vlseg8e64ff_v", "vlseg2e8ff_v", "vlseg3e8ff_v", "vlseg4e8ff_v",
    "vlseg5e8ff_v", "vlseg6e8ff_v", "vlseg7e8ff_v", "vlseg8e8ff_v",
    "vlseg2se8ff_v", "vlseg3se8ff_v", "vlseg4se8ff_v", "vlseg5se8ff_v",
    "vlseg6se8ff_v", "vlseg7se8ff_v", "vlseg8se8ff_v",
};

///@todo consider splitting instructions like "vsseg2se8_v" into a separate group
///@brief Vector unit stride segmented stores in Section 7.8.1 of risc-v-spec-1.0
///@details instructions like `vsseg<nf>e<eew>.v vd, (rs1), vm` or `vsseg<nf>e<eew>.v vs3, (rs1), vm`
static const std::string vector_segmented_stores[] =
{
    "vsseg2e16_v", "vsseg3e16_v", "vsseg4e16_v", "vsseg5e16_v",
    "vsseg6e16_v", "vsseg7e16_v", "vsseg8e16_v", "vsseg2e32_v",
    "vsseg3e32_v", "vsseg4e32_v", "vsseg5e32_v", "vsseg6e32_v",
    "vsseg7e32_v", "vsseg8e32_v", "vsseg2e64_v", "vsseg3e64_v",
    "vsseg4e64_v", "vsseg5e64_v", "vsseg6e64_v", "vsseg7e64_v",
    "vsseg8e64_v", "vsseg2e8_v", "vsseg3e8_v", "vsseg4e8_v",
    "vsseg5e8_v", "vsseg6e8_v", "vsseg7e8_v", "vsseg8e8_v",
    "vsseg2se8_v", "vsseg3se8_v", "vsseg4se8_v", "vsseg5se8_v",
    "vsseg6se8_v", "vsseg7se8_v", "vsseg8se8_v",
};

///@brief Vector unit stride segmented loads in Section 7.8.2 of risc-v-spec-1.0
///@details instructions like `vlsseg<nf>e<eew>.v vd, (rs1), rs2, vm` or `vsseg<nf>e<eew>.v vs3, (rs1), rs2, vm`
static const std::string vector_strided_segmented_loads[] =
{
    "vlsseg2e1024_v", "vlsseg3e1024_v", "vlsseg4e1024_v",
    "vlsseg5e1024_v", "vlsseg6e1024_v", "vlsseg7e1024_v",
    "vlsseg8e1024_v", "vlsseg2e128_v", "vlsseg3e128_v",
    "vlsseg4e128_v", "vlsseg5e128_v", "vlsseg6e128_v",
    "vlsseg7e128_v", "vlsseg8e128_v", "vlsseg2e16_v",
    "vlsseg3e16_v", "vlsseg4e16_v", "vlsseg5e16_v",
    "vlsseg6e16_v", "vlsseg7e16_v", "vlsseg8e16_v",
    "vlsseg2e256_v", "vlsseg3e256_v", "vlsseg4e256_v",
    "vlsseg5e256_v", "vlsseg6e256_v", "vlsseg7e256_v",
    "vlsseg8e256_v","vlsseg2e32_v", "vlsseg3e32_v",
    "vlsseg4e32_v", "vlsseg5e32_v", "vlsseg6e32_v",
    "vlsseg7e32_v", "vlsseg8e32_v", "vlsseg2e512_v",
    "vlsseg3e512_v", "vlsseg4e512_v", "vlsseg5e512_v",
    "vlsseg6e512_v", "vlsseg7e512_v", "vlsseg8e512_v",
    "vlsseg2e64_v", "vlsseg3e64_v", "vlsseg4e64_v",
    "vlsseg5e64_v", "vlsseg6e64_v", "vlsseg7e64_v",
    "vlsseg8e64_v",
};

///@brief Vector unit stride segmented loads in Section 7.8.2 of risc-v-spec-1.0
///@details instructions like `vssseg<nf>e<eew>.v vs3, (rs1), rs2, vm`
static const std::string vector_strided_segmented_stores[] =
{
    "vssseq2e1024_v", "vssseq3e1024_v", "vssseq4e1024_v",
    "vssseq5e1024_v", "vssseq6e1024_v", "vssseq7e1024_v",
    "vssseq8e1024_v", "vssseq2e128_v", "vssseq3e128_v",
    "vssseq4e128_v", "vssseq5e128_v", "vssseq6e128_v",
    "vssseq7e128_v", "vssseq8e128_v", "vssseq2e16_v",
    "vssseq3e16_v", "vssseq4e16_v", "vssseq5e16_v",
    "vssseq6e16_v", "vssseq7e16_v", "vssseq8e16_v",
    "vssseq2e256_v", "vssseq3e256_v", "vssseq4e256_v",
    "vssseq5e256_v", "vssseq6e256_v", "vssseq7e256_v",
    "vssseq8e256_v","vssseq2e32_v", "vssseq3e32_v",
    "vssseq4e32_v", "vssseq5e32_v", "vssseq6e32_v",
    "vssseq7e32_v", "vssseq8e32_v", "vssseq2e512_v",
    "vssseq3e512_v", "vssseq4e512_v", "vssseq5e512_v",
    "vssseq6e512_v", "vssseq7e512_v", "vssseq8e512_v",
    "vssseq2e64_v", "vssseq3e64_v", "vssseq4e64_v",
    "vssseq5e64_v", "vssseq6e64_v", "vssseq7e64_v",
    "vssseq8e64_v",
};

///@brief Vector indexed unordered segmented loads in section 7.8.3 of risc-v-spec-1.0
///@details instructions like vluxseg<nf>ei<eew>.v
static const std::string vector_unordered_indexed_segmented_loads[] =
{
    "vluxseg2ei8_v", "vluxseg3ei8_v", "vluxseg4ei8_v",
    "vluxseg5ei8_v", "vluxseg6ei8_v", "vluxseg7ei8_v",
    "vluxseg8ei8_v", "vluxseg2ei16_v",
    "vluxseg3ei16_v", "vluxseg4ei16_v", "vluxseg5ei16_v",
    "vluxseg6ei16_v", "vluxseg7ei16_v", "vluxseg8ei16_v",
    "vluxseg2ei32_v", "vluxseg3ei32_v",
    "vluxseg4ei32_v", "vluxseg5ei32_v", "vluxseg6ei32_v",
    "vluxseg7ei32_v", "vluxseg8ei32_v",
    "vluxseg2ei64_v", "vluxseg3ei64_v", "vluxseg4ei64_v",
    "vluxseg5ei64_v", "vluxseg6ei64_v", "vluxseg7ei64_v",
    "vluxseg8ei64_v",
};
///@brief Vector indexed ordered segmented loads in section 7.8.3 of risc-v-spec-1.0
///@details instructions like vluxseg<nf>ei<eew>.v
static const std::string vector_ordered_indexed_segmented_loads[] =
{
    "vloxseg2ei8_v", "vloxseg3ei8_v", "vloxseg4ei8_v",
    "vloxseg5ei8_v", "vloxseg6ei8_v", "vloxseg7ei8_v",
    "vloxseg8ei8_v", "vloxseg2ei16_v",
    "vloxseg3ei16_v", "vloxseg4ei16_v", "vloxseg5ei16_v",
    "vloxseg6ei16_v", "vloxseg7ei16_v", "vloxseg8ei16_v",
    "vloxseg2ei32_v", "vloxseg3ei32_v",
    "vloxseg4ei32_v", "vloxseg5ei32_v", "vloxseg6ei32_v",
    "vloxseg7ei32_v", "vloxseg8ei32_v",
    "vloxseg2ei64_v", "vloxseg3ei64_v", "vloxseg4ei64_v",
    "vloxseg5ei64_v", "vloxseg6ei64_v", "vloxseg7ei64_v",
    "vloxseg8ei64_v",
};

///@brief Vector indexed unordered segmented stores in section 7.8.3 of risc-v-spec-1.0
///@details instructions like vsuxseg<nf>ei<eew>.v
static const std::string vector_unordered_indexed_segmented_stores[] =
{
    "vsuxseg2ei8_v", "vsuxseg3ei8_v", "vsuxseg4ei8_v",
    "vsuxseg5ei8_v", "vsuxseg6ei8_v", "vsuxseg7ei8_v",
    "vsuxseg8ei8_v", "vsuxseg2ei16_v",
    "vsuxseg3ei16_v", "vsuxseg4ei16_v", "vsuxseg5ei16_v",
    "vsuxseg6ei16_v", "vsuxseg7ei16_v", "vsuxseg8ei16_v",
    "vsuxseg2ei32_v", "vsuxseg3ei32_v",
    "vsuxseg4ei32_v", "vsuxseg5ei32_v", "vsuxseg6ei32_v",
    "vsuxseg7ei32_v", "vsuxseg8ei32_v",
    "vsuxseg2ei64_v", "vsuxseg3ei64_v", "vsuxseg4ei64_v",
    "vsuxseg5ei64_v", "vsuxseg6ei64_v", "vsuxseg7ei64_v",
    "vsuxseg8ei64_v",
};
///@brief Vector indexed ordered segmented stores in section 7.8.3 of risc-v-spec-1.0
///@details instructions like vsoxseg<nf>ei<eew>.v
static const std::string vector_ordered_indexed_segmented_stores[] =
{
    "vsoxseg2ei8_v", "vsoxseg3ei8_v", "vsoxseg4ei8_v",
    "vsoxseg5ei8_v", "vsoxseg6ei8_v", "vsoxseg7ei8_v",
    "vsoxseg8ei8_v", "vsoxseg2ei16_v", "vsoxseg3ei16_v",
    "vsoxseg4ei16_v", "vsoxseg5ei16_v", "vsoxseg6ei16_v",
    "vsoxseg7ei16_v", "vsoxseg8ei16_v", "vsoxseg2ei32_v",
    "vsoxseg3ei32_v", "vsoxseg4ei32_v", "vsoxseg5ei32_v",
    "vsoxseg6ei32_v", "vsoxseg7ei32_v", "vsoxseg8ei32_v",
    "vsoxseg2ei64_v", "vsoxseg3ei64_v", "vsoxseg4ei64_v",
    "vsoxseg5ei64_v", "vsoxseg6ei64_v", "vsoxseg7ei64_v",
    "vsoxseg8ei64_v",
};

///@brief Vector whole register loads in section 7.9 of risc-v-spec-1.0
static const std::string vector_whole_register_loads[] =
{
    "vl1re8_v", "vl1re16_v", "vl1re32_v", "vl1re64_v",
    "vl2re8_v", "vl2re16_v", "vl2re32_v", "vl2re64_v",
    "vl4re8_v", "vl4re16_v", "vl4re32_v", "vl4re64_v",
    "vl8re8_v","vl8re16_v", "vl8re32_v", "vl8re64_v",
};

///@brief Vector whole register stores in section 7.9 of risc-v-spec-1.0
static const std::string vector_whole_register_stores[] =
{
    "vs1r_v", "vs2r_v", "vs4r_v", "vs8r_v",
};

///@todo assign traits
///@brief Vector integer compare instructions defined in section 11.8 of risc-v-spec-1.0
static const std::string vector_integer_compare[] =
{
    "vmseq_vi", "vmseq_vv", "vmseq_vx",
    "vmsne_vi", "vmsne_vv", "vmsne_vx",
    "vmsltu_vv", "vmsltu_vx", "vmslt_vv", "vmslt_vx",
    "vmsleu_vi", "vmsleu_vv", "vmsleu_vx",
    "vmsle_vi", "vmsle_vv", "vmsle_vx",
    "vmsgtu_vi", "vmsgtu_vx", "vmsgt_vi", "vmsgt_vx",
};
///@todo assign traits
///@brief Vector mask register instructions defined in section 15.1 of risc-v-spec-1.0
static const std::string vector_mask_register[] =
{
    "vmand_mm", "vmnand_mm", "vmandn_mm", "vmxor_mm", "vmor_mm",
    "vmnor_mm", "vmorn_mm", "vmxnor_mm"
};

///@todo assign traits
///@brief other vector mask instructions defined in section 15 of risc-v-spec-1.0
static const std::string vector_mask_other[] =
{
    "vcpop_m", "vfirst_m", "vmsbf_m", "vmsif_m", "vmsof_m",
    "viota_m", "vid_v",
};

///@brief Vector Single-Width Integer Add and Subtract from section 11.1
static const std::string vector_integer_arithetic[] =
{
    "vadd_vi", "vadd_vv", "vadd_vx", "vsub_vv", "vsub_vx",
    "vrsub_vi", "vrsub_vx", "vneg_v",
};

///@brief Vector Widening Integer Add and Subtract from section 11.2
static const std::string vector_widening_integer_arithetic[] =
{
    "vwaddu_vx", "vwaddu_vv", "vwsubu_vv", "vwsubu_vx",
    "vwadd_vx", "vwadd_vv", "vwsub_vv", "vwsub_vx",
    "vwaddu_wv", "vwaddu_wx", "vwsubu_wv", "vwsubu_wx",
    "vwadd_wv", "vwadd_wx", "vwsub_wv", "vwsub_wx",
};

///@brief Vector Integer Extension from section 11.3
static const std::string vector_integer_extension[] =
{
    "vzext_vf2", "vzext_vf4", "vzext_vf8",
    "vsext_vf2", "vsext_vf4", "vsext_vf8",
};

///@brief Vector Widening Integer Add and Subtract from section 11.4
static const std::string vector_integer_with_carry_arithetic[] =
{
    "vadc_vim", "vadc_vvm", "vadc_vxm", "vmadc_vim",
    "vmadc_vv", "vmadc_vvm", "vmadc_vx", "vmadc_vxm",
    "vmadc_vi", "vsbc_vvm", "vsbc_vxm", "vmsbc_vvm",
    "vmsbc_vv", "vmsbc_vx", "vmsbc_vxm",
};
///@brief Vector bitwise logical operations from section 11.5
static const std::string vector_bitwise_logical[] =
{
    "vand_vi", "vand_vv", "vand_vx", "vor_vi", "vor_vv",
    "vor_vx", "vxor_vi", "vxor_vv", "vxor_vx", "vnot_v"
};
///@brief Vector single width shift from section 11.6
static const std::string vector_single_width_shift[] =
{
    "vsll_vi", "vsll_vv", "vsll_vx",
    "vsrl_vi", "vsrl_vv", "vsrl_vx",
    "vsra_vi", "vsra_vv", "vsra_vx",
};
///@brief Vector single width shift from section 11.7
static const std::string vector_narrowing_shift_right[] =
{
    "vnsrl_wi", "vnsrl_wv", "vnsrl_wx",
    "vnsra_wi", "vnsra_wv", "vnsra_wx",
};

///@brief Vector integer min-max from section 11.9
static const std::string vector_integer_minmax[] =
{
    "vminu_vv", "vminu_vx", "vmin_vv", "vmin_vx",
    "vmaxu_vv", "vmaxu_vx", "vmax_vv", "vmax_vx",
};

///@brief Vector single width integer multiply from section 11.10
static const std::string vector_single_width_integer_multiply[] =
{
    "vmul_vv", "vmul_vx", "vmulh_vv", "vmulh_vx",
    "vmulhu_vv", "vmulhu_vx", "vmulhsu_vv", "vmulhsu_vx",
};

///@brief Vector single width integer divide from section 11.11
static const std::string vector_single_width_integer_divide[] =
{
    "vdivu_vv", "vdivu_vx", "vdiv_vv", "vdiv_vx",
    "vremu_vv", "vremu_vx", "vrem_vv", "vrem_vx",
};

///@brief Vector widening integer multiply from section 11.12
static const std::string vector_widening_integer_multiply[] =
{
    "vwmul_vv", "vwmul_vx", "vwmulu_vv", "vwmulu_vx",
    "vwmulsu_vv", "vwmulsu_vx",
};

///@brief Vector integer multiply-add from section 11.13
static const std::string vector_integer_multiply_add[] =
{
    "vmacc_vv", "vmacc_vx", "vnmsac_vv", "vnmsac_vx",
    "vmadd_vv", "vmadd_vx", "vnmsub_vv", "vnmsub_vx",
};
///@brief Vector widening integer multiply-add from section 11.14
static const std::string vector_widening_integer_multiply_add[] =
{
    "vwmaccu_vv", "vwmaccu_vx", "vwmacc_vv", "vwmacc_vx",
    "vwmaccsu_vv", "vwmaccsu_vx", "vwmaccus_vx",
};
///@brief Vector integer merge from section 11.15
static const std::string vector_integer_merge[] =
{
    "vmerge_vim", "vmerge_vvm", "vmerge_vxm",
};
///@brief Vector integer move from section 11.16
static const std::string vector_integer_move[] =
{
    "vmv_v_v", "vmv_v_x",
};

///@brief Vector integer move immediate from section 11.16
static const std::string vector_integer_load_immediate[] =
{
    "vmv_v_i",
};

///@brief Vector Single-Width Integer Reduction Instructions from section 14.1
static const std::string vector_integer_reduction[] =
{
    "vredsum_vs", "vredmaxu_vs", "vredmax_vs", "vredminu_vs",
    "vredmin_vs", "vredand_vs", "vredor_vs", "vredxor_vs",
};

///@brief Vector Widening Integer Reduction Instructions from section 14.2
static const std::string vector_widening_integer_reduction[] =
{
    "vwredsum_vs", "vwredsumu_vs",
};

///@brief Vector Permutation Instructions from section 16
static const std::string vector_permutation[] =
{
    "vmv_s_x", "vmv_x_s",  "vslide1down_vx", "vslide1up_vx",
    "vslidedown_vi", "vslidedown_vx", "vslideup_vi",
};
///@brief Vector Gather Instructions from section 16.4
static const std::string vector_gather[] =
{
    "vrgather_vi", "vrgather_vv", "vrgather_vx", "vrgatherei16_vv",
};

///@brief Vector Compress Instructions from section 16.5
static const std::string vector_compress[] =
{
    "vcompress_vm",
};

///@brief Vector Whole Register Move Instructions from section 16.6
static const std::string vector_whole_register_move[] =
{
    "vmv1r_v", "vmv2r_v", "vmv4r_v", "vmv8r_v",
};

const std::vector<std::string> other_user_pcodeOps = {
    "unimp", "trap", "ebreak", "ecall", "fence", "fence.i",
    "fence_tso", "add_uw", "clmul", "clmulh", "clmulr",
    "clz", "clzw", "ctz", "ctzw", "orc_b", "rev8", "rev_b",
    "minu", "maxu", "min", "max", "pack", "packh", "packw",
    "zext_h", "cpop", "cpopw", "rol", "rolw", "ror", "rorw",
    "rori", "roriw", "bclr", "bclri", "bexti", "binv", "binvi",
    "bset", "bseti", "sext_b", "sext_h", "unzip", "zip",
    "xperm_b", "xperm_n", "insb", "maxw", "mulr64", "pkbb16",
    "pkbt16", "sub64", "swap8", "wexti", "wfi", "sfence.vm",
    "sfence.vma", "sfence.w.inval", "sfence.inval.ir",
    "hfence.vvma", "hfence.gvma",
    "vaadd_vv", "vaadd_vx", "vaaddu_vv", "vaaddu_vx",
    "vamoaddei16_v", "vamoaddei32_v", "vamoaddei64_v",
    "vamoaddei8_v", "vamoandei16_v", "vamoandei32_v",
    "vamoandei64_v", "vamoandei8_v", "vamomaxei16_v",
    "vamomaxei32_v", "vamomaxei64_v", "vamomaxei8_v",
    "vamomaxuei16_v", "vamomaxuei32_v", "vamomaxuei64_v",
    "vamomaxuei8_v", "vamominei16_v", "vamominei32_v",
    "vamominei64_v", "vamominei8_v", "vamominuei16_v",
    "vamominuei32_v", "vamominuei64_v", "vamominuei8_v",
    "vamoorei16_v", "vamoorei32_v", "vamoorei64_v", "vamoorei8_v",
    "vamoswapei16_v", "vamoswapei32_v", "vamoswapei64_v",
    "vamoswapei8_v", "vamoxorei16_v", "vamoxorei32_v",
    "vamoxorei64_v", "vamoxorei8_v", "vasub_vv", "vasub_vx", "vasubu_vv", "vasubu_vx",
    "vdot_vv", "vdotu_vv", "vfadd_vf", "vfadd_vv", "vfclass_v",
    "vfcvt_fxv", "vfcvt_fxuv", "vfcvt_rtzxfv", "vfcvt_rtzxufv",
    "vfcvt_xfv", "vfcvt_xufv", "vfdiv_vf", "vfdiv_vv", "vfdot_vv",
    "vfmacc_vf", "vfmacc_vv", "vfmadd_vf", "vfmadd_vv",
    "vfmax_vf", "vfmax_vv", "vfmerge_vfm", "vfmin_vf", "vfmin_vv",
    "vfmsac_vf", "vfmsac_vv", "vfmsub_vf", "vfmsub_vv", "vfmul_vf",
    "vfmul_vv", "vfmv_fs", "vfmv_sf", "vfmv_vf", "vfncvt_ffw",
    "vfncvt_fxw", "vfncvt_fxuw", "vfncvt_rod_ffw", "vfncvt_rtz_xfw",
    "vfncvt_rtz_xufw", "vfncvt_xfw", "vfncvt_xufw", "vfnmacc_vf",
    "vfnmacc_vv", "vfnmadd_vf", "vfnmadd_vv", "vfnmsac_vf", "vfnmsac_vv",
    "vfnmsub_vf", "vfnmsub_vv", "vfrdiv_vf", "vfredmax_vs",
    "vfredmin_vs", "vfredosum_vs", "vfredusum_vs", "vfrsub_vf",
    "vfsgnj_vf", "vfsgnj_vv", "vfsgnjn_vf", "vfsgnjn_vv", "vfneg_vv",
    "vfsgnjx_vf", "vfsgnjx_vv", "vfslide1down_vf", "vfslide1up_vf",
    "vfsqrt_v", "vfsqrt7_v", "vfrec7_v", "vfsub_vf", "vfsub_vv",
    "vfwadd_vf", "vfwadd_vv", "vfwadd_wf", "vfwadd_wv", "vfwcvt_f_f_v",
    "vfwcvt_f_x_v", "vfwcvt_f_xu_v", "vfwcvt_rtz_x_f_v",
    "vfwcvt_rtz_xu_f_v", "vfwcvt_x_f_v", "vfwcvt_xu_f_v",
    "vfwmacc_vf", "vfwmacc_vv", "vfwmsac_vf", "vfwmsac_vv",
    "vfwmul_vf", "vfwmul_vv", "vfwnmacc_vf", "vfwnmacc_vv",
    "vfwnmsac_vf", "vfwnmsac_vv", "vfwredosum_vs", "vfwredusum_vs",
    "vfwsub_vf", "vfwsub_vv", "vfwsub_wf", "vfwsub_wv",
    "vlm8_v", "vlxei16_v", "vlxei32_v", "vlxei64_v", "vlxei8_v",
    "vmfeq_vf", "vmfeq_vv", "vmfge_vf", "vmfgt_vf", "vmfle_vf", "vmfle_vv",
    "vmflt_vf", "vmflt_vv", "vmfne_vf", "vmfne_vv",
    "vnclip_wi", "vnclip_wv", "vnclip_wx",
    "vnclipu_wi", "vnclipu_wv", "vnclipu_wx", "vncvt_xxw",
    "vqmacc_vv", "vqmacc_vx", "vqmaccsu_vv",
    "vqmaccsu_vx", "vqmaccu_vv", "vqmaccu_vx", "vqmaccus_vx",
    "vsadd_vi", "vsadd_vv", "vsadd_vx", "vsaddu_vi", "vsaddu_vv",
    "vsaddu_vx", "vslideup_vx", "vsmul_vv", "vsmul_vx",
    "vssra_vi", "vssra_vv", "vssra_vx", "vssrl_vi", "vssrl_vv", "vssrl_vx",
    "vssub_vv", "vssub_vx", "vssubu_vv", "vssubu_vx",
    "vwcvt_xxv", "vwcvtu_xxv",
    "aes64ds", "aes64dsm", "aes64im", "aes64ks1i", "aes64ks2", "loadfp_const",
    "fmin_m", "fmax_m", "copybitsH", "trunc_h", "trunc_hu", "fmv_x_h",
    "fmv_h_x", "fclass_h", "aes64es", "aes64esm", "sha256sig0",
    "sha256sig1", "sha256sum0", "sha256sum1", "sha512sig0h", "sha512sig0l",
    "sha512sig1h", "sha512sig1l", "sha512sum0r", "sha512sum1r",
    "sha512sig0", "sha512sig1", "sha512sum0", "sha512sum1",
    "vandn_vv", "vandn_vx", "vbrev_v", "vbrev8_v", "vrev8_v", "vclz_v", "vctz_v",
    "vcpop_v", "vrol_vv", "vrol_vx", "vror_vv", "vror_vx", "vror_vi",
    "vwsll_vv", "vwsll_vx", "vwsll_vi", "vclmul_vv", "vclmul_vx",
    "vclmulh_vv", "vclmulh_vx",
    "vaesdf_vv", "vaesdf_vs", "vaesdm_vv",
    "vaesdm_vs", "vaesem_vv", "vaesem_vs", "vaesef_vv", "vaesef_vs",
    "vaeskf1_vi", "vaeskf2_vi", "vaesz_vs", "vsha2ch_vv", "vsha2cl_vv",
    "vsha2ms_vv", "vghsh_vv", "vgmul_vv", "vsm3c_vi", "vsm3me_vv",
    "vsm4k_vi", "vsm4r_vv", "vsm4r_vs", "custom0", "custom0.rs1",
    "custom0.rs1.rs2", "custom0.rd", "custom0.rd.rs1",
    "custom0.rd.rs1.rs2", "custom1", "custom1.rs1", "custom1.rs1.rs2",
    "custom1.rd", "custom1.rd.rs1", "custom1.rd.rs1.rs2", "custom2",
    "custom2.rs1", "custom2.rs1.rs2", "custom2.rd", "custom2.rd.rs1",
    "custom2.rd.rs1.rs2", "custom3", "custom3.rs1", "custom3.rs1.rs2",
    "custom3.rd", "custom3.rd.rs1", "custom3.rd.rs1.rs2"
};

std::map<int, RiscvUserPcode*> riscvPcodeMap;      /// lookup a user pcode given Ghidra's sleigh index
std::map<std::string, ghidra::uintb> riscvNameToGhidraId;
std::map<std::string, RiscvUserPcode*> riscvNameToPcodeMap;

const RiscvUserPcode* RiscvUserPcode::getUserPcode(const ghidra::PcodeOp& op)
{
    if (op.code() != ghidra::CPUI_CALLOTHER)
        return nullptr;
    if (op.numInput() < 1)
        return nullptr;
    ghidra::uintb userop_index = op.getIn(0)->getOffset();
    return riscvPcodeMap[userop_index];
}

void RiscvUserPcode::loadAsmOpcodes()
{
    for (const auto& opName: vector_setup)
    {
        uint64_t traits = OP_IS_VSET;
        if (opName.find("vsetivli_", 0) == 0)
            traits |= OP_IS_IMMEDIATE;
        int elementSize = 0;
        int multiplier = 0;
        if (opName.find("e8") != std::string::npos)
            elementSize = 1;
        else if (opName.find("e16") != std::string::npos)
            elementSize = 2;
        else if (opName.find("e32") != std::string::npos)
            elementSize = 4;
        else if (opName.find("e64") != std::string::npos)
            elementSize = 8;
        if ((opName.find("m1") != std::string::npos) ||
            (opName.find("mf") != std::string::npos))
            multiplier = 1;
        else if (opName.find("m2") != std::string::npos)
            multiplier = 2;
        else if (opName.find("m4") != std::string::npos)
            multiplier = 4;
        else if (opName.find("m8") != std::string::npos)
            multiplier = 8;
        // the most common tail and mask option is tama
        std::string tm = opName.substr(opName.size() - 4);
        bool isMaskUnchanged;
        bool isTailUnchanged;
        if (tm != "tama")
        {
            isMaskUnchanged = tm.substr(2) == "mu";
            isTailUnchanged = tm.substr(0, 2) == "tu";
        }
        else
        {
            isMaskUnchanged = false;
            isTailUnchanged = false;
        }
        RiscvUserPcode* pcode = new RiscvUserPcode(opName, traits, new VsetContext(elementSize, multiplier, isTailUnchanged, isMaskUnchanged));
        riscvNameToPcodeMap.insert(std::make_pair(opName, pcode));
    }
    for (const auto& opName: vector_unit_stride_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD)));
    for (const auto& opName: vector_unit_stride_stores)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_STORE)));
    for (const auto& opName: vector_unit_stride_mask_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_MASK)));
    for (const auto& opName: vector_unit_stride_mask_stores)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_STORE|OP_IS_MASK)));
    for (const auto& opName: vector_strided_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_STRIDED)));
    for (const auto& opName: vector_strided_stores)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_STORE|OP_IS_STRIDED)));
    for (const auto& opName: vector_strided_indexed_unordered_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_INDEXED)));
    for (const auto& opName: vector_strided_indexed_ordered_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_INDEXED|OP_IS_ORDERED)));
    for (const auto& opName: vector_strided_indexed_unordered_stores)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_STORE|OP_IS_INDEXED)));
    for (const auto& opName: vector_strided_indexed_ordered_stores)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_STORE|OP_IS_INDEXED|OP_IS_ORDERED)));
    for (const auto& opName: vector_fault_only_first_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_FAULT_ONLY_FIRST)));
    for (const auto& opName: vector_segmented_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_SEGMENTED)));
    for (const auto& opName: vector_segmented_stores)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_STORE|OP_IS_SEGMENTED)));
    for (const auto& opName:  vector_segmented_fault_only_first_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_FAULT_ONLY_FIRST|OP_IS_SEGMENTED)));
    for (const auto& opName: vector_strided_segmented_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_STRIDED|OP_IS_SEGMENTED)));
    for (const auto& opName: vector_strided_segmented_stores)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_STORE|OP_IS_STRIDED|OP_IS_SEGMENTED)));
    for (const auto& opName: vector_unordered_indexed_segmented_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_INDEXED|OP_IS_SEGMENTED)));
    for (const auto& opName: vector_ordered_indexed_segmented_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_INDEXED|OP_IS_SEGMENTED|OP_IS_ORDERED)));
    for (const auto& opName: vector_unordered_indexed_segmented_stores)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_STORE|OP_IS_INDEXED|OP_IS_SEGMENTED)));
    for (const auto& opName: vector_ordered_indexed_segmented_stores)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_STORE|OP_IS_INDEXED|OP_IS_SEGMENTED|OP_IS_ORDERED)));
    for (const auto& opName: vector_whole_register_loads)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_WHOLE_REGISTER)));
    for (const auto& opName: vector_integer_compare)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_COMPARISON)));
    for (const auto& opName: vector_mask_register)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_MASK_COMPARISON)));
    for (const auto& opName: vector_mask_other)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_MASK_OTHER)));
    for (const auto& opName: vector_integer_arithetic)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_ARITH)));
    for (const auto& opName: vector_widening_integer_arithetic)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_WIDENING_INTEGER_ARITH)));
    for (const auto& opName: vector_integer_extension)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_EXTENSION)));
    for (const auto& opName: vector_integer_with_carry_arithetic)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_CARRY_ARITH)));
    for (const auto& opName: vector_bitwise_logical)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_BITWISE_LOGICAL)));
    for (const auto& opName: vector_single_width_shift)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_SINGLE_WIDTH_SHIFT)));
    for (const auto& opName: vector_narrowing_shift_right)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_NARROWING_SHIFT_RIGHT)));
    for (const auto& opName: vector_integer_minmax)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_MINMAX)));
    for (const auto& opName: vector_single_width_integer_multiply)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_SINGLE_WIDTH_MULTIPLY)));
    for (const auto& opName: vector_single_width_integer_divide)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_SINGLE_WIDTH_DIVIDE)));
    for (const auto& opName: vector_widening_integer_multiply)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_WIDENING_MULTIPLY)));
    for (const auto& opName: vector_integer_multiply_add)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_MULTIPLY_ADD)));
    for (const auto& opName: vector_widening_integer_multiply_add)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_WIDENING_INTEGER_MULTIPLY_ADD)));
    for (const auto& opName: vector_integer_merge)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_MERGE)));
    for (const auto& opName: vector_integer_move)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_INTEGER_MOVE)));
    for (const auto& opName: vector_integer_load_immediate)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, OP_IS_LOAD|OP_IS_IMMEDIATE)));
    ///@todo need to research traits for the following instructions
    for (const auto& opName: vector_integer_reduction)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, 0x0LU)));
    for (const auto& opName: vector_widening_integer_reduction)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, 0x0LU)));
    for (const auto& opName: vector_permutation)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, 0x0LU)));
    for (const auto& opName: vector_gather)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, 0x0LU)));
    for (const auto& opName: vector_compress)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, 0x0LU)));
    for (const auto& opName: vector_whole_register_move)
        riscvNameToPcodeMap.insert(std::make_pair(opName, new RiscvUserPcode(opName, 0x0LU)));
}
RiscvUserPcode::RiscvUserPcode(const std::string& asmName, uint64_t traitsParam) :
    asmOpcode(asmName),
    ghidraOp(0),
    traits(traitsParam),
    context(nullptr)
{
}
RiscvUserPcode::RiscvUserPcode(const std::string& asmName, uint64_t traitsParam, OpContext* contextParam) :
    asmOpcode(asmName),
    ghidraOp(0),
    traits(traitsParam),
    context(contextParam)
{
}
void RiscvUserPcode::staticCleanup()
{
    for (auto &pair : riscv_vector::riscvNameToPcodeMap)
    {
        RiscvUserPcode* code = pair.second;
        if ((code != nullptr) && (code->context != nullptr))
        {
            delete code->context;
        }
        delete code;
    }
    riscvNameToPcodeMap.clear();
    riscvNameToGhidraId.clear();
}
}