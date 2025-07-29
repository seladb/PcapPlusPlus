#include "MemoryLeakListener.hpp"

#include <memplumber.h>

namespace pcpp
{
	namespace test
	{
		void MemoryLeakListener::OnTestStart(const ::testing::TestInfo& testInfo)
		{
			MemPlumber::start();
		}

		void MemoryLeakListener::OnTestEnd(const ::testing::TestInfo& testInfo)
		{
			std::size_t memLeakCount = 0;
			std::uint64_t memLeakSize = 0;
			MemPlumber::memLeakCheck(memLeakCount, memLeakSize);
			MemPlumber::stop();
			// MemPlumber::stopAndDropTrackedMemory();

			if (memLeakCount > 0 || memLeakSize > 0)
			{
				FAIL() << "Memory leak found! " << memLeakCount << " objects and " << memLeakSize << " [bytes] leaked";
			}
		}

	}  // namespace testing
}  // namespace pcpp