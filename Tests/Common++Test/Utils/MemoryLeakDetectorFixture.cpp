#include "MemoryLeakDetectorFixture.hpp"

namespace pcpp
{
	namespace test
	{
		bool MemoryLeakDetectorTest::skipMemLeakCheck = false;
		std::once_flag MemoryLeakDetectorTest::m_MSVC_WarningPrinted;
	}  // namespace testing
}  // namespace pcpp