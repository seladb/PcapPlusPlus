#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "IpAddress.h"

namespace pcpp
{
	TEST(IPv4AddressTest, IPv4AddressStatics)
	{
		IPv4Address const& ipZero = IPv4Address::Zero;
		EXPECT_EQ(ipZero.toInt(), 0);
		EXPECT_EQ(ipZero.toString(), "0.0.0.0");

		IPv4Address const& ipMulticastLower = IPv4Address::MulticastRangeLowerBound;
		EXPECT_EQ(ipMulticastLower.toInt(), 0x000000E0);
		EXPECT_EQ(ipMulticastLower.toString(), "224.0.0.0");

		IPv4Address const& ipMulticastUpper = IPv4Address::MulticastRangeUpperBound;
		EXPECT_EQ(ipMulticastUpper.toInt(), 0xFFFFFFEF);
		EXPECT_EQ(ipMulticastUpper.toString(), "239.255.255.255");

		EXPECT_TRUE(IPv4Address::isValidIPv4Address("222.146.254.245"));
		EXPECT_FALSE(IPv4Address::isValidIPv4Address("222.146.300.245"));
		EXPECT_FALSE(IPv4Address::isValidIPv4Address("bogus string"));
	};

	TEST(IPv4AddressTest, IPv4AddressBasics)
	{
		IPv4Address ipDefault;
		EXPECT_EQ(ipDefault.toInt(), 0);
		EXPECT_EQ(ipDefault.toString(), "0.0.0.0");
		EXPECT_EQ(ipDefault, pcpp::IPv4Address::Zero);

		IPv4Address ipString("0.0.0.1");
		EXPECT_EQ(ipString.toInt(), 0x01000000);
		EXPECT_EQ(ipString.toString(), "0.0.0.1");
		EXPECT_THROW(IPv4Address("0.0.0.644"), std::invalid_argument) << "IPv4Address does not throw for out of bounds IP string.";
		EXPECT_THROW(IPv4Address("bogusString"), std::invalid_argument) << "IPv4Address does not throw for non-IP string.";

		IPv4Address ipUint32(0x085201A0);
		EXPECT_EQ(ipUint32.toInt(), 0x085201A0);
		EXPECT_EQ(ipUint32.toString(), "160.1.82.8");

		std::array<uint8_t, 4> ipArrayBuffer = {192, 100, 1, 1};
		IPv4Address ipUint8Raw(ipArrayBuffer.data());
		EXPECT_EQ(ipUint8Raw.toInt(), 0x010164C0);
		EXPECT_EQ(ipUint8Raw.toString(), "192.100.1.1");
		EXPECT_EQ(ipUint8Raw.toByteArray(), ipArrayBuffer);
		EXPECT_TRUE(0 == std::memcmp(ipArrayBuffer.data(), ipUint8Raw.toBytes(), 4));

		IPv4Address ipUint8Array(ipArrayBuffer);
		EXPECT_EQ(ipUint8Array.toInt(), 0x010164C0);
		EXPECT_EQ(ipUint8Array.toString(), "192.100.1.1");
		EXPECT_EQ(ipUint8Array.toByteArray(), ipArrayBuffer);
		EXPECT_TRUE(0 == std::memcmp(ipArrayBuffer.data(), ipUint8Array.toBytes(), 4));

		EXPECT_TRUE(ipUint8Raw == ipUint8Array) << "Comparison operator '==' does not compare equal values correctly.";
		EXPECT_FALSE(ipUint8Raw == ipDefault) << "Comparison operator '==' does not compare unequal values correctly.";
		EXPECT_FALSE(ipUint8Raw != ipUint8Array) << "Comparison operator '!=' does not compare equal values correctly.";
		EXPECT_TRUE(ipUint8Raw != ipDefault) << "Comparison operator '!=' does not compare unequal values correctly.";

		EXPECT_TRUE(ipDefault < ipString) << "Comparison operator '<' does not compare less than values correctly.";
		EXPECT_FALSE(ipString < ipDefault) << "Comparison operator '<' does not compare less than values correctly.";
	};

	TEST(IPv4AddressTest, Multicast)
	{
		IPv4Address underMulticastBound(0x000000D1);
		EXPECT_FALSE(underMulticastBound.isMulticast());

		IPv4Address atLowerMulticastBound(0x000000E0);
		EXPECT_TRUE(atLowerMulticastBound.isMulticast());

		IPv4Address inMulticastRange(0x000000EF);
		EXPECT_TRUE(inMulticastRange.isMulticast());
		
		IPv4Address atUpperMulticastBound(0xFFFFFFEF);
		EXPECT_TRUE(atUpperMulticastBound.isMulticast());
		
		IPv4Address overMulticastBound(0x000000F0);
		EXPECT_FALSE(overMulticastBound.isMulticast());
	};

	TEST(IPv4AddressTest, MatchNetwork)
	{
		FAIL() << "Not Implemented";
	};

	TEST(IPv6AddressTest, IPv6Statics)
	{
		IPv6Address const& ipZero = IPv6Address::Zero;
		EXPECT_EQ(ipZero.toString(), "::");
		EXPECT_THAT(ipZero.toByteArray(), ::testing::Each(0));

		IPv6Address const& ipMulticastLower = IPv6Address::MulticastRangeLowerBound;
		EXPECT_EQ(ipMulticastLower.toString(), "ff00::");
		EXPECT_THAT(ipMulticastLower.toByteArray(), ::testing::ElementsAre(0xFF, 0x00, 0x00, 0x00));
	};

	TEST(IPv6AddressTest, IPv6AddressBasics)
	{
		IPv6Address ipDefault;
		
		FAIL() << "Not Implemented";
	};

	TEST(IPAddressTest, IPAddressTest)
	{
		FAIL() << "Not Implemented";
	};

	TEST(IPv4NetworkTest, IPv4NetworkTest)
	{
		FAIL() << "Not Implemented";
	};

	TEST(IPv6NetworkTest, IPv6NetworkTest)
	{
		FAIL() << "Not Implemented";
	};

	TEST(IPNetworkTest, IPNetworkTest)
	{
		FAIL() << "Not Implemented";
	};
}  // namespace pcpp