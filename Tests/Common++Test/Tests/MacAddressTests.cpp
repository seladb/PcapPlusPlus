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

	TEST(MacAddressTest, CopyToBuffer)
	{
		pcpp::MacAddress macAddr(1, 2, 3, 4, 5, 6);

		constexpr size_t expectedRequiredBytes = 6;
		std::array<uint8_t, expectedRequiredBytes> expected = { 1, 2, 3, 4, 5, 6 };

		// Test query mode
		EXPECT_EQ(macAddr.copyTo(nullptr, 0), 6);

		// Test with null buffer and non-zero size
		EXPECT_THROW(macAddr.copyTo(nullptr, 1), std::invalid_argument);

		std::array<uint8_t, 10> buffer{};

		// Test with smaller buffer.
		EXPECT_EQ(macAddr.copyTo(buffer.data(), 5), expectedRequiredBytes);
		EXPECT_THAT(buffer, ::testing::Each(::testing::Eq(0)));

		// Test with precise buffer
		buffer.fill(0);
		EXPECT_EQ(macAddr.copyTo(buffer.data(), expectedRequiredBytes), expectedRequiredBytes);
		EXPECT_EQ(std::memcmp(buffer.data(), expected.data(), expectedRequiredBytes), 0);
		EXPECT_TRUE(std::all_of(buffer.begin() + 6, buffer.end(), [](uint8_t x) { return x == 0; }));

		// Test with a buffer that is larger
		buffer.fill(0);
		EXPECT_EQ(macAddr.copyTo(buffer.data(), buffer.size()), expectedRequiredBytes);
		EXPECT_EQ(std::memcmp(buffer.data(), expected.data(), expectedRequiredBytes), 0);
		EXPECT_TRUE(std::all_of(buffer.begin() + 6, buffer.end(), [](uint8_t x) { return x == 0; }));
	}

	TEST(MacAddressTest, CopyToNewBuffer)
	{
		pcpp::MacAddress macAddr(1, 2, 3, 4, 5, 6);

		constexpr size_t expectedRequiredBytes = 6;
		std::array<uint8_t, expectedRequiredBytes> expected = { 1, 2, 3, 4, 5, 6 };

		uint8_t* newBuffer = nullptr;
		size_t newBufferSize = 0;

		EXPECT_THROW(macAddr.copyToNewBuffer(nullptr, newBufferSize), std::invalid_argument)
		    << "IPv6Address::copyToNewBuffer does not throw for null buffer pointer.";

		EXPECT_TRUE(macAddr.copyToNewBuffer(&newBuffer, newBufferSize));
		std::unique_ptr<uint8_t[]> bufferGuard(newBuffer);

		ASSERT_NE(newBuffer, nullptr) << "IPv6Address::copyToNewBuffer did not allocate a new buffer.";
		ASSERT_EQ(newBufferSize, expectedRequiredBytes)
		    << "IPv6Address::copyToNewBuffer did not return the correct size.";

		EXPECT_EQ(std::memcmp(newBuffer, expected.data(), expectedRequiredBytes), 0)
		    << "IPv6Address::copyToNewBuffer did not copy the address correctly.";
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
