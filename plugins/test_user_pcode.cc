

/**
 * @file test_user_pcode.cc
 * @author thixotropist
 * @brief Provide gtest unit tests for user pcode instruction handlers
 */
#include "gtest/gtest.h"
#include "spdlog/spdlog.h"
//#include "spdlog/sinks/basic_file_sink.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include "Ghidra/Features/Decompiler/src/decompile/cpp/op.hh"

#include "framework.hh"
#include "user_pcode.hh"
#include "riscv.hh"
#include "vector_ops.hh"

namespace riscv_vector
{

/**
 * @brief A sample of RISC-V user pcodeOps found in a specific
 * RISC-V Architecture dump.
 * @details Note that this dump includes all user pcodes,
 * not just vector instruction user pcodes.
 */

/**
 * @brief Set up the global framework for tests,
 * including global data on RISC-V vector instructions
 */
class HandlerTest : public testing::Test {
  protected:
  /**
   * @brief Set up the global framework for tests,
   * including global data on RISC-V vector instructions
   */
  static void SetUpTestSuite() {
    ghidra::pLogger = spdlog::stdout_color_mt("gtest_logger");
    spdlog::set_default_logger(ghidra::pLogger);
    // log levels are trace, debug, info, warn, error and critical.
    ghidra::pLogger->set_level(spdlog::level::info);
    ghidra::pLogger->flush_on(spdlog::level::info);

    RiscvUserPcode::loadAsmOpcodes();
    // assign dummy Ghidra indices
    int opIndex = 0;
    for (const auto& [name, code] : riscvNameToPcodeMap)
    {
        opIndex++;
        code->assignGhidraId(opIndex);
        riscvNameToGhidraId.insert(std::make_pair(name, opIndex));
        riscvPcodeMap.insert(std::make_pair(opIndex, code));
        opIndex++;
    }
    ghidra::pLogger->info("Found and indexed {0:d} defined assembly instructions", opIndex);
  }
/**
 * @brief Destroy the test suite resources
 * including global data on RISC-V vector instructions
 */
  static void TearDownTestSuite() {
    RiscvUserPcode::staticCleanup();
    ghidra::pLogger->flush();
  }
};
/**
 * @brief Verify the mapping between SLEIGH assembly instructions and Ghidra integer IDs.
 */
TEST_F(HandlerTest, riscvNameToGhidraId)
{
    auto it = riscvNameToGhidraId.find("vsetvli_e8m1tama");
    EXPECT_NE(it, riscvNameToGhidraId.end())
        << "Reference userPcodeOp not found in riscvNameToGhidraId";
}
/**
 * @brief Verify the mapping between Ghidra integer ID and RiscvUserPcode descriptor objects
 */
TEST_F(HandlerTest, riscvPcodeMap)
{
    EXPECT_GE(riscvPcodeMap.size(), 100)
        << "Far too few userPcodeOps found for this architecture";
    RiscvUserPcode *userOp = riscvPcodeMap[riscvNameToGhidraId["vsetvli_e8m1tama"]];
    EXPECT_NE(userOp, nullptr) <<
        "vsetvli_e8m1tama userPcode not found in riscvPcodeMap";
    EXPECT_NE(userOp->traits, 0) <<
        "vsetvli_e8m1tama is not recognized as a vector operation";
}

/**
 * @brief Verify basic traits are set for basic vset instructions
 */
TEST_F(HandlerTest, traits)
{
    RiscvUserPcode *userOp = riscvPcodeMap[riscvNameToGhidraId["vsetvli_e8m1tama"]];
    EXPECT_EQ(userOp->asmOpcode, "vsetvli_e8m1tama") <<
        "User opcode names are corrupted";
    EXPECT_EQ(userOp->traits, OP_IS_VSET) <<
        "vsetvli_e8m1tama has improper traits";
    OpContext* context = userOp->context;
    EXPECT_EQ(context->cType, VSET_CONTEXT)
        << "vsetvli_e8m1tama has improper context";

    EXPECT_EQ(context->getElementSize(), 1);
    EXPECT_EQ(context->getMultiplier(), 1);
    EXPECT_FALSE(context->getTailUnchanged());
    EXPECT_FALSE(context->getMaskUnchanged());
    // repeat with a more complex example
    userOp = riscvPcodeMap[riscvNameToGhidraId["vsetivli_e16m8tumu"]];
    EXPECT_EQ(userOp->traits, OP_IS_VSET|OP_IS_IMMEDIATE) <<
        "vsetivli_e16m1tumu has improper traits";
    context = userOp->context;
    EXPECT_EQ(context->cType, VSET_CONTEXT)
        << "vsetivli_e16m1tumu has improper context";
    EXPECT_EQ(context->getElementSize(), 2);
    EXPECT_EQ(context->getMultiplier(), 8);
    EXPECT_TRUE(context->getTailUnchanged());
    EXPECT_TRUE(context->getMaskUnchanged());
}
}