#include <gtest/gtest.h>
#include <memplumber.h>

#include <mutex>

namespace pcpp
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
			skipMemLeakCheck = false;
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
			if(!skipMemLeakCheck)
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

	bool MemoryLeakDetectorTest::skipMemLeakCheck = false;
	std::once_flag MemoryLeakDetectorTest::m_MSVC_WarningPrinted;
}  // namespace pcpp
