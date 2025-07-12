#include <iostream>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "PcapPlusPlusVersion.h"

int main(int argc, char* argv[])
{
	std::cout << "PcapPlusPlus Common++Test"
	             "\nPcapPlusPlus version: "
	          << pcpp::getPcapPlusPlusVersionFull()       //
	          << "\nBuilt: " << pcpp::getBuildDateTime()  //
	          << "\nBuilt from: " << pcpp::getGitInfo() << std::endl;

	::testing::InitGoogleMock(&argc, argv);
	return RUN_ALL_TESTS();
}
