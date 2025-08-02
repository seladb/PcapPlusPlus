#include <iostream>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "Logger.h"
#include "PcapPlusPlusVersion.h"
#include "Utils/MemoryLeakListener.hpp"

int main(int argc, char* argv[])
{
	std::cout << "PcapPlusPlus Common++Test"
	             "\nPcapPlusPlus version: "
	          << pcpp::getPcapPlusPlusVersionFull()       //
	          << "\nBuilt: " << pcpp::getBuildDateTime()  //
	          << "\nBuilt from: " << pcpp::getGitInfo() << std::endl;

	::testing::InitGoogleMock(&argc, argv);

	// The logger singleton looks like a memory leak. Invoke it before starting the memory check
	// Disables context pooling to avoid false positives in the memory leak check, as the contexts persist in the pool.
	pcpp::Logger::getInstance().useContextPooling(false);

#ifdef NDEBUG
	// TODO: Do we still need this? The issue seems to be closed?
	std::cout
	    << "Disabling memory leak check in MSVC Release builds due to caching logic in stream objects that looks like a memory leak:\n"
	       "     https://github.com/cpputest/cpputest/issues/786#issuecomment-148921958"
	    << std::endl;
#else
	// GTest sometimes allocates memory? which isn't freed before TearDown is called causing false positives and
	// crashes.

	// auto& eventListeners = ::testing::UnitTest::GetInstance()->listeners();
	// eventListeners.Append(new pcpp::test::MemoryLeakListener());
#endif

	return RUN_ALL_TESTS();
}
