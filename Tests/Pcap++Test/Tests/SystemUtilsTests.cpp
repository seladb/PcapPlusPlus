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

PTF_TEST_CASE(TestSystemCore)
{
	pcpp::SystemCore core = { 0x01, 0 };
	PTF_ASSERT_EQUAL(core.getShortCoreMask(), 0x01);

	pcpp::SystemCore overShortMaskCore{ 0x00, 32 };
	PTF_ASSERT_RAISES(overShortMaskCore.getShortCoreMask(), std::out_of_range,
	                  "Core ID is out of range for a short core mask");
}

PTF_TEST_CASE(TestLongCoreMask)
{
	auto numOfCores = pcpp::getNumOfCores();

	auto allCoresMask = pcpp::LongCoreMask::fromAllCores();
	PTF_ASSERT_EQUAL(allCoresMask.Mask.count(),
	                 numOfCores > pcpp::LongCoreMask::MaxCoreCount ? pcpp::LongCoreMask::MaxCoreCount : numOfCores);

	auto fromShortMask = pcpp::LongCoreMask(pcpp::createCoreMaskFromCoreIds({ 0, 1, 2, 3 }));
	PTF_ASSERT_EQUAL(fromShortMask.Mask.count(), 4);
	PTF_ASSERT_TRUE(fromShortMask.Mask.test(0));
	PTF_ASSERT_TRUE(fromShortMask.Mask.test(1));
	PTF_ASSERT_TRUE(fromShortMask.Mask.test(2));
	PTF_ASSERT_TRUE(fromShortMask.Mask.test(3));

	auto fromSystemCore = pcpp::LongCoreMask(pcpp::SystemCores::Core5);
	PTF_ASSERT_EQUAL(fromSystemCore.Mask.count(), 1);
	PTF_ASSERT_TRUE(fromSystemCore.Mask.test(5));

	auto fromCoreVector = pcpp::LongCoreMask(
	    std::vector<pcpp::SystemCore>{ pcpp::SystemCores::Core0, pcpp::SystemCores::Core2, pcpp::SystemCores::Core4 });
	PTF_ASSERT_EQUAL(fromCoreVector.Mask.count(), 3);
	PTF_ASSERT_TRUE(fromCoreVector.Mask.test(0));
	PTF_ASSERT_TRUE(fromCoreVector.Mask.test(2));
	PTF_ASSERT_TRUE(fromCoreVector.Mask.test(4));
}
