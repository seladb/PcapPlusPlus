#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "MacAddress.h"

namespace pcpp
{
	TEST(MacAddressTest, MacAddressStatics)
	{
		EXPECT_EQ(MacAddress::Zero.toString(), "00:00:00:00:00:00");
	};

	TEST(MacAddressTest, MacAddressBasics)
	{
		MacAddress macAddr1;
		EXPECT_EQ(macAddr1.toString(), "00:00:00:00:00:00");

		std::array<uint8_t, 6> addr = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
		MacAddress macAddr2(addr.data());
		EXPECT_EQ(macAddr2.toString(), "00:11:22:33:44:55");

		MacAddress macAddr3(addr);
		EXPECT_EQ(macAddr3.toString(), "00:11:22:33:44:55");

		MacAddress macAddr4("00:11:22:33:44:55");
		EXPECT_EQ(macAddr4.toString(), "00:11:22:33:44:55");
		EXPECT_THROW(MacAddress("00:11:22:33:44"), std::invalid_argument);
		EXPECT_THROW(MacAddress("00:11:22:33:44:55:66"), std::invalid_argument);
		EXPECT_THROW(MacAddress("bogus string"), std::invalid_argument);

		MacAddress macAddr5(std::string("00:11:22:33:44:55"));
		EXPECT_EQ(macAddr5.toString(), "00:11:22:33:44:55");

		MacAddress macAddr6(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
		EXPECT_EQ(macAddr6.toString(), "00:11:22:33:44:55");

		MacAddress macAddr7{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
		EXPECT_EQ(macAddr7.toString(), "00:11:22:33:44:55");
		EXPECT_THROW(MacAddress({ 0x00, 0x11, 0x22, 0x33, 0x44 }), std::invalid_argument);
		EXPECT_THROW(MacAddress({ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }), std::invalid_argument);

		MacAddress macAddr8 = "00:11:22:33:44:55";
		EXPECT_EQ(macAddr8.toString(), "00:11:22:33:44:55");

		MacAddress macAddr9 = std::string("00:11:22:33:44:55");
		EXPECT_EQ(macAddr9.toString(), "00:11:22:33:44:55");

		MacAddress macAddr10 = MacAddress("00:11:22:33:44:55");
		EXPECT_EQ(macAddr10.toString(), "00:11:22:33:44:55");

		EXPECT_FALSE(macAddr1 == macAddr2) << "Comparison operator '==' does not compare unequal values correctly.";
		EXPECT_TRUE(macAddr2 == macAddr3) << "Comparison operator '==' does not compare equal values correctly.";

		EXPECT_TRUE(macAddr1 != macAddr2) << "Comparison operator '!=' does not compare unequal values correctly.";
		EXPECT_FALSE(macAddr2 != macAddr3) << "Comparison operator '!=' does not compare equal values correctly.";
	};
}  // namespace pcpp
