#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "GeneralUtils.h"

namespace pcpp
{
	TEST(GeneralUtilsTests, byteArrayToHexString)
	{
		std::array<uint8_t, 3> byteArr = { 0xaa, 0x2b, 0x10 };
		EXPECT_EQ(byteArrayToHexString(byteArr.data(), byteArr.size()), "aa2b10");
	};

	TEST(GeneralUtilsTests, hexStringToByteArray)
	{
		std::array<uint8_t, 3> resultByteArr = { 0 };
		EXPECT_EQ(hexStringToByteArray("aa2b10", resultByteArr.data(), resultByteArr.size()), 3);
		EXPECT_EQ(resultByteArr, (std::array<uint8_t, 3>{ 0xaa, 0x2b, 0x10 }));
	};

	TEST(GeneralUtilsTests, cross_platform_memmem)
	{
		const char haystack[] = "Hello, World!";
		const char needle[] = "World";
		EXPECT_EQ(cross_platform_memmem(haystack, sizeof(haystack), needle,
		                                sizeof(needle) - 1 /* ignore the null terminator */),
		          haystack + 7);
	};

	TEST(GeneralUtilsTests, align)
	{
		EXPECT_EQ(align<4>(3), 4);
		EXPECT_EQ(align<4>(4), 4);
		EXPECT_EQ(align<4>(5), 8);
	};
}  // namespace pcpp
