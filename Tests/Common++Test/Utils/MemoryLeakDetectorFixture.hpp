#include <gtest/gtest.h>
#include <memplumber.h>

namespace pcpp
{
	class MemoryLeakDetectorTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			MemPlumber::start();
		}

		void TearDown() override
		{
			std::size_t memLeakCount = 0;
			std::uint64_t memLeakSize = 0;
			MemPlumber::memLeakCheck(memLeakCount, memLeakSize);
			MemPlumber::stopAndFreeAllMemory();

			if (memLeakCount > 0 || memLeakSize > 0)
			{
				FAIL() << "Memory leak found! " << memLeakCount << " objects and " << memLeakSize << " [bytes] leaked";
			}
		}
	};

}  // namespace pcpp
