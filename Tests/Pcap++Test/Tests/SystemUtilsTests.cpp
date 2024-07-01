#include "../TestDefinition.h"
#include "SystemUtils.h"
#include <bitset>

PTF_TEST_CASE(TestSystemCoreUtils)
{
	auto numOfCores = pcpp::getNumOfCores();
	PTF_ASSERT_GREATER_THAN(numOfCores, 1);

	std::bitset<32> bs(pcpp::getCoreMaskForAllMachineCores());
	PTF_ASSERT_EQUAL(bs.count(), numOfCores);

	auto coreVector =
	    std::vector<pcpp::SystemCore>{ pcpp::SystemCores::Core0, pcpp::SystemCores::Core2, pcpp::SystemCores::Core4 };
	PTF_ASSERT_EQUAL(pcpp::createCoreMaskFromCoreVector(coreVector), 0b10101);

	auto coreIdVector = std::vector<int>{ 1, 3, 5 };
	PTF_ASSERT_EQUAL(pcpp::createCoreMaskFromCoreIds(coreIdVector), 0b101010);

	std::vector<pcpp::SystemCore> coreVector2;
	pcpp::createCoreVectorFromCoreMask(0b10101, coreVector2);
	PTF_ASSERT_TRUE(coreVector == coreVector2);
}
