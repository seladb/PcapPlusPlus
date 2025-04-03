#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "SystemUtils.h"

namespace pcpp
{

	TEST(CoreMaskTest, CreateCoreMaskFromCoreIdsMethod)
	{
		const std::vector<int> coreIds{ 0, 1, 2, 3 };
		CoreMask mask = createCoreMaskFromCoreIds(coreIds);

		EXPECT_EQ(mask, 0x0F);
	};

	TEST(CoreMaskTest, CreateCoreMaskFromCoreVectorMethod)
	{

		const std::vector<SystemCore> cores{
			SystemCores::Core0,
			SystemCores::Core1,
			SystemCores::Core2,
			SystemCores::Core3,
		};

		CoreMask mask = createCoreMaskFromCoreVector(cores);

		EXPECT_EQ(mask, 0x0F);
	};

	TEST(CoreMaskTest, CreateCoreVectorFromCoreMaskMethod)
	{
		const CoreMask mask = 0x0F;
		const std::vector<SystemCore> expectedCores = {
			SystemCores::Core0,
			SystemCores::Core1,
			SystemCores::Core2,
			SystemCores::Core3,
		};
		std::vector<SystemCore> cores;

		createCoreVectorFromCoreMask(mask, cores);

		EXPECT_EQ(cores, expectedCores);
	};
}  // namespace pcpp
