#include <iostream>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "PcapPlusPlusVersion.h"

int main(int argc, char* argv[])
{
	std::cout << "PcapPlusPlus version: " << pcpp::getPcapPlusPlusVersionFull() << '\n'
	          << "Built: " << pcpp::getBuildDateTime() << '\n'
	          << "Built from: " << pcpp::getGitInfo() << std::endl;

	::testing::InitGoogleMock(&argc, argv);
	return RUN_ALL_TESTS();
}
