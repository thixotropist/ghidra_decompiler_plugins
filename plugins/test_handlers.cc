#include "framework.hh"
#include "riscv.hh"
#include "vector_ops.hh"

#include "gtest/gtest.h"

TEST(TraitsTest, Initialization) {
    EXPECT_EQ(5, 5);
    EXPECT_EQ(0, 0);
}