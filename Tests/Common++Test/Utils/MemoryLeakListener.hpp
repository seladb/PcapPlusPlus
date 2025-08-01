#pragma once

#include <gtest/gtest.h>

namespace pcpp
{
	namespace test
	{
		class MemoryLeakListener : public ::testing::EmptyTestEventListener
		{
		public:
			void OnTestStart(const ::testing::TestInfo& testInfo) override;
			void OnTestEnd(const ::testing::TestInfo& testInfo) override;
		};
	}  // namespace test

}  // namespace pcpp
