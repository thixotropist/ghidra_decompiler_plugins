/**
 * @file vector_instr_handlers.cc
 * @author thixotropist
 * @brief Lamda function handlers for common RISC-V vector functions
 * @date 2026-8-16
 *
 * @copyright Copyright (c) 2026
 */

#include <functional>

#include "Ghidra/Features/Decompiler/src/decompile/cpp/types.h"
#include "Ghidra/Features/Decompiler/src/decompile/cpp/type.hh"

#include "framework.hh"
#include "riscv.hh"
#include "vector_ops.hh"

namespace riscv_vector{

class VectorTraits
{
  public:
    std::vector<VectorOperation*> vectorOps;
    std::vector<VectorOperation*> vLogicalOps;
    std::vector<VectorOperation*> vComparisonOps;
    uint flags;
};
//using userPcodeOpHandler = std::function<void(VectorTraits* traits, ghidra::PcodeOp* op)>;
static std::map<ghidra::uintb, std::function<void(VectorTraits* traits, ghidra::PcodeOp* op)>> opHandlers;

static auto setupOp = [](VectorTraits* traits, ghidra::PcodeOp* op) -> void {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorSetup, op);
            traits->vectorOps.push_back(vOp);
        };
static auto loadOp = [](VectorTraits* traits, ghidra::PcodeOp* op) -> void {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoad, op);
            traits->vectorOps.push_back(vOp);
        };
static auto storeOp = [](VectorTraits* traits, ghidra::PcodeOp* op) -> void {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorStore, op);
            traits->vectorOps.push_back(vOp);
        };
static auto comparisonOp = [](VectorTraits* traits, ghidra::PcodeOp* op) -> void {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorComparison, op);
            traits->vectorOps.push_back(vOp);
            traits->vComparisonOps.push_back(vOp);
        };
static auto logicalOp = [](VectorTraits* traits, ghidra::PcodeOp* op) -> void {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorComparison, op);
            traits->vectorOps.push_back(vOp);
            traits->vLogicalOps.push_back(vOp);
        };

void init_handlers(VectorTraits& traits)
{
    // instructions found in many vector stanzas, starting with vector_memcpy
    opHandlers[riscvNameToGhidraId["vsetvli_e8m1tama"]] = setupOp;
    opHandlers[riscvNameToGhidraId["vle8_v"]] = loadOp;
    opHandlers[riscvNameToGhidraId["vse8_v"]] = storeOp;

    // instructions found in vector_strlen stanzas
    opHandlers[riscvNameToGhidraId["vle8ff_v"]] =
        [](VectorTraits* traits, ghidra::PcodeOp* op) {
            traits->flags |= RISCV_VEC_INSN_FAULT_ONLY_FIRST;
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoadFF, op);
            traits->vectorOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vmseq_vi"]] = comparisonOp;
    opHandlers[riscvNameToGhidraId["vfirst_m"]] = logicalOp;
    // instructions found in vector_strcmp stanzas
    opHandlers[riscvNameToGhidraId["vmsne_vv"]] = comparisonOp;
    opHandlers[riscvNameToGhidraId["vmor_mm"]] = logicalOp;
    // instructions found in typed range copy sequences
    opHandlers[riscvNameToGhidraId["vsetvli_e8mf8tama"]] =
        [](VectorTraits* traits, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorSetup, op);
            traits->vectorOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vsetvli_e8mf4tama"]] = setupOp;
    opHandlers[riscvNameToGhidraId["vsetvli_e8mf2tama"]] = setupOp;
    opHandlers[riscvNameToGhidraId["vle16_v"]] = loadOp;
    opHandlers[riscvNameToGhidraId["vse16_v"]] = storeOp;
    opHandlers[riscvNameToGhidraId["vle32_v"]] = loadOp;
    opHandlers[riscvNameToGhidraId["vse32_v"]] = storeOp;
    opHandlers[riscvNameToGhidraId["vle64_v"]] = loadOp;

    opHandlers[riscvNameToGhidraId["vse64_v"]] = storeOp;
    // vector whole register loads and stores
    opHandlers[riscvNameToGhidraId["vl1re8_v"]] =
        [](VectorTraits* traits, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoad, op);
            traits->vectorOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vl1re16_v"]] =
        [](VectorTraits* traits, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoad, op);
            traits->vectorOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vl1re32_v"]] =
        [](VectorTraits* traits, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoad, op);
            traits->vectorOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vl1re64_v"]] =
        [](VectorTraits* traits, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorLoad, op);
            traits->vectorOps.push_back(vOp);
        };
    opHandlers[riscvNameToGhidraId["vs1r_v"]] =
        [](VectorTraits* traits, ghidra::PcodeOp* op) {
            VectorOperation* vOp = new VectorOperation(OperationType::vectorStore, op);
            traits->vectorOps.push_back(vOp);
        };
}
}