#pragma once

#include <gtest/gtest.h>
#include <memplumber.h>

#include <mutex>

namespace pcpp
{
	namespace test
	{
		class MemoryLeakDetectorTest : public ::testing::Test
		{
			using Base = ::testing::Test;

		public:
			static void SetUpTestSuite()
			{
#ifdef NDEBUG
				// TODO: Do we still need this? The issue seems to be closed?
				skipMemLeakCheck = true;
				std::call_once(m_MSVC_WarningPrinted, [] {
					std::cout
					    << "Disabling memory leak check in MSVC Release builds due to caching logic in stream objects that looks like a memory leak:\n"
					       "     https://github.com/cpputest/cpputest/issues/786#issuecomment-148921958"
					    << std::endl;
				});
#else
				// GTest sometimes allocates memory? which isn't freed before TearDown is called causing false positives and crashes.
				skipMemLeakCheck = true;
#endif
			}

		protected:
			void SetUp() override
			{
				Base::SetUp();

				if (!skipMemLeakCheck)
				{
					MemPlumber::start();
				}
			}

			void TearDown() override
			{
				if (!skipMemLeakCheck)
				{
					std::size_t memLeakCount = 0;
					std::uint64_t memLeakSize = 0;
					MemPlumber::memLeakCheck(memLeakCount, memLeakSize);
					MemPlumber::stopAndFreeAllMemory();

					if (memLeakCount > 0 || memLeakSize > 0)
					{
						FAIL() << "Memory leak found! " << memLeakCount << " objects and " << memLeakSize
						       << " [bytes] leaked";
					}
				}

				Base::TearDown();
			}

		private:
			static bool skipMemLeakCheck;
			static std::once_flag m_MSVC_WarningPrinted;
		};
	}  // namespace test

}  // namespace pcpp

// Macro to define a test case in the MemoryLeakDetectorTest suite
// The macro is copied from the Google Test framework GTEST_TEST macro definition in gtest.h
#define PTF_MEMLEAK_TEST(test_suite_name, test_name)                                                                   \
	GTEST_TEST_(test_suite_name, test_name, pcpp::test::MemoryLeakDetectorTest,                                        \
	            ::testing::internal::GetTypeId<pcpp::test::MemoryLeakDetectorTest>())

#ifndef PTF_NO_TEST_OVERRIDE
#	define TEST(test_suite_name, test_name) PTF_MEMLEAK_TEST(test_suite_name, test_name)
#endif  // !PTF_NO_TEST_OVERRIDE
