#include "pch.h"

#include <cstring>
#include <sstream>

#include "MacAddress.h"

namespace pcpp
{
	TEST(MacAddressTest, DefaultConstructor)
	{
		pcpp::MacAddress mac;
		std::array<uint8_t, 6> expected = { 0, 0, 0, 0, 0, 0 };
		EXPECT_EQ(std::memcmp(mac.getRawData(), expected.data(), 6), 0);
	}

	TEST(MacAddressTest, ByteArrayConstructor)
	{
		uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
		pcpp::MacAddress mac(addr);
		EXPECT_EQ(std::memcmp(mac.getRawData(), addr, 6), 0);
	}

	TEST(MacAddressTest, StdArrayConstructor)
	{
		std::array<uint8_t, 6> addr = { 1, 2, 3, 4, 5, 6 };
		pcpp::MacAddress mac(addr);
		EXPECT_EQ(std::memcmp(mac.getRawData(), addr.data(), 6), 0);
	}

	TEST(MacAddressTest, StringConstructor)
	{
		std::string addr = "01:02:03:04:05:06";
		pcpp::MacAddress mac(addr);
		std::array<uint8_t, 6> expected = { 1, 2, 3, 4, 5, 6 };
		EXPECT_EQ(std::memcmp(mac.getRawData(), expected.data(), 6), 0);

		EXPECT_THROW(pcpp::MacAddress("01:02:03:04:05"), std::invalid_argument);
		EXPECT_THROW(pcpp::MacAddress("01:02:03:04:05:06:07"), std::invalid_argument);
		EXPECT_THROW(pcpp::MacAddress("bogus string"), std::invalid_argument);
	}

	TEST(MacAddressTest, OctetConstructor)
	{
		pcpp::MacAddress mac(1, 2, 3, 4, 5, 6);
		std::array<uint8_t, 6> expected = { 1, 2, 3, 4, 5, 6 };
		EXPECT_EQ(std::memcmp(mac.getRawData(), expected.data(), 6), 0);
	}

	TEST(MacAddressTest, InitializerListConstructor)
	{
		pcpp::MacAddress mac({ 1, 2, 3, 4, 5, 6 });
		std::array<uint8_t, 6> expected = { 1, 2, 3, 4, 5, 6 };
		EXPECT_EQ(std::memcmp(mac.getRawData(), expected.data(), 6), 0);
	}

	TEST(MacAddressTest, EqualityOperator)
	{
		pcpp::MacAddress mac1(1, 2, 3, 4, 5, 6);
		pcpp::MacAddress mac2(1, 2, 3, 4, 5, 6);
		EXPECT_TRUE(mac1 == mac2);

		pcpp::MacAddress mac3(1, 2, 3, 4, 5, 7);
		EXPECT_FALSE(mac1 == mac3);
	}

	TEST(MacAddressTest, InequalityOperator)
	{
		pcpp::MacAddress mac1(1, 2, 3, 4, 5, 6);
		pcpp::MacAddress mac2(1, 2, 3, 4, 5, 7);
		EXPECT_TRUE(mac1 != mac2);

		pcpp::MacAddress mac3(1, 2, 3, 4, 5, 6);
		EXPECT_FALSE(mac1 != mac3);
	}

	TEST(MacAddressTest, AssignmentOperator)
	{
		pcpp::MacAddress mac;
		mac = { 1, 2, 3, 4, 5, 6 };
		std::array<uint8_t, 6> expected = { 1, 2, 3, 4, 5, 6 };
		EXPECT_EQ(std::memcmp(mac.getRawData(), expected.data(), 6), 0);
	}

	TEST(MacAddressTest, ToString)
	{
		pcpp::MacAddress mac(1, 2, 3, 4, 5, 6);
		EXPECT_EQ(mac.toString(), "01:02:03:04:05:06");
	}

	TEST(MacAddressTest, CopyToAllocatedArray)
	{
		pcpp::MacAddress mac(1, 2, 3, 4, 5, 6);
		uint8_t* arr = nullptr;
		mac.copyTo(&arr);
		std::array<uint8_t, 6> expected = { 1, 2, 3, 4, 5, 6 };
		EXPECT_EQ(std::memcmp(arr, expected.data(), 6), 0);
		delete[] arr;
	}

	TEST(MacAddressTest, CopyToPreAllocatedArray)
	{
		pcpp::MacAddress mac(1, 2, 3, 4, 5, 6);
		std::array<uint8_t, 6> arr;
		mac.copyTo(arr.data());
		std::array<uint8_t, 6> expected = { 1, 2, 3, 4, 5, 6 };
		EXPECT_EQ(arr, expected);
	}

	TEST(MacAddressTest, OutputStreamOperator)
	{
		MacAddress macAddr(1, 2, 3, 4, 5, 6);
		std::stringstream stream;
		stream << macAddr;
		EXPECT_EQ(stream.str(), "01:02:03:04:05:06");
	};

	TEST(MacAddressTest, ConstantHelpers)
	{
		EXPECT_EQ(MacAddress::Zero, MacAddress(0, 0, 0, 0, 0, 0));
		EXPECT_EQ(MacAddress::Broadcast, MacAddress(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
	};
}  // namespace pcpp
