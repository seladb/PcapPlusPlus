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

	auto coreVector2 = pcpp::createCoreVectorFromCoreMask(0b10101);
	PTF_ASSERT_TRUE(coreVector == coreVector2);
}

PTF_TEST_CASE(TestSystemCore)
{
	pcpp::SystemCore core1(1);
	PTF_ASSERT_EQUAL(core1.Id, 1);
	PTF_ASSERT_EQUAL(core1.getShortCoreMask(), 0x02);

	pcpp::SystemCore core = { 0x01, 0 };
	PTF_ASSERT_EQUAL(core.getShortCoreMask(), 0x01);

	pcpp::SystemCore overShortMaskCore{ 0x00, 32 };
	PTF_ASSERT_RAISES(overShortMaskCore.getShortCoreMask(), std::out_of_range,
	                  "Core ID is out of range for a short core mask");
}

PTF_TEST_CASE(TestLongCoreMask)
{
	using pcpp::SystemCore;
	using pcpp::SystemCores;
	using pcpp::LongCoreMask;

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
	PTF_ASSERT_TRUE(fromSystemCore.test(pcpp::SystemCores::Core5));

	auto fromCoreVector = pcpp::LongCoreMask(
	    std::vector<pcpp::SystemCore>{ pcpp::SystemCores::Core0, pcpp::SystemCores::Core2, pcpp::SystemCores::Core4 });
	PTF_ASSERT_EQUAL(fromCoreVector.Mask.count(), 3);
	PTF_ASSERT_TRUE(fromCoreVector.Mask.test(0));
	PTF_ASSERT_TRUE(fromCoreVector.Mask.test(2));
	PTF_ASSERT_TRUE(fromCoreVector.Mask.test(4));
	PTF_ASSERT_TRUE(fromCoreVector.test(pcpp::SystemCores::Core0));
	PTF_ASSERT_TRUE(fromCoreVector.test(pcpp::SystemCores::Core2));
	PTF_ASSERT_TRUE(fromCoreVector.test(pcpp::SystemCores::Core4));

	// Test equality operators
	PTF_ASSERT_TRUE(LongCoreMask(0b1010) == LongCoreMask(0b1010));
	PTF_ASSERT_TRUE(LongCoreMask(0b1010) != LongCoreMask(0b0101));
	
	// Test comparisons with a single SystemCore
	// TODO: Optimization oppotunity:
	//   Forward equality of LongCoreMask a and SystemCore b to a.test(b) instead of creating a new LongCoreMask for b.
	PTF_ASSERT_TRUE(LongCoreMask(0b1) == SystemCores::Core0);
	PTF_ASSERT_FALSE(LongCoreMask(0b11) == SystemCores::Core0);

	PTF_ASSERT_TRUE(LongCoreMask(0b1) == 0b1);
	PTF_ASSERT_TRUE(0b11 == LongCoreMask(0b11));
	PTF_ASSERT_FALSE(LongCoreMask(0b1) == 0b10);

	// Test bitwise operations on LongCoreMask
	auto lmask1 = pcpp::LongCoreMask(0b1100);
	auto lmask2 = pcpp::LongCoreMask(0b0011);
	
	PTF_ASSERT_TRUE(pcpp::LongCoreMask(0b1111) == (lmask1 | lmask2));
	PTF_ASSERT_TRUE(pcpp::LongCoreMask(0b0000) == (lmask1 & lmask2));

	auto lmask1plusCores01 = lmask1 | pcpp::SystemCores::Core0 | pcpp::SystemCores::Core1;
	PTF_ASSERT_TRUE(lmask1plusCores01 == (lmask1 | lmask2));

	pcpp::LongCoreMask lmaskCores1 = lmask2 & pcpp::SystemCores::Core1;
	PTF_ASSERT_TRUE(lmaskCores1 == pcpp::SystemCores::Core1);
	PTF_ASSERT_TRUE(pcpp::SystemCores::Core1 == lmaskCores1);

	auto lmaskXor = lmask1 ^ pcpp::LongCoreMask(0b1011);
	PTF_ASSERT_TRUE(lmaskXor == pcpp::LongCoreMask(0b0111));

	// Toggle Core0 On and Core2 Off
	lmaskXor = lmask1 ^ pcpp::SystemCores::Core0 ^ pcpp::SystemCores::Core2;
	PTF_ASSERT_TRUE(lmaskXor == pcpp::LongCoreMask(0b1001));
}
