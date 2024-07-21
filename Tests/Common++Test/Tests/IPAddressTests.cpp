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
		EXPECT_THROW(IPv4Address("0.0.0.644"), std::invalid_argument)
		    << "IPv4Address does not throw for out of bounds IP string.";
		EXPECT_THROW(IPv4Address("bogusString"), std::invalid_argument)
		    << "IPv4Address does not throw for non-IP string.";

		IPv4Address ipUint32(0x085201A0);
		EXPECT_EQ(ipUint32.toInt(), 0x085201A0);
		EXPECT_EQ(ipUint32.toString(), "160.1.82.8");

		std::array<uint8_t, 4> ipArrayBuffer = { 192, 100, 1, 1 };
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

	TEST(IPv6AddressTest, IPv6AddressStatics)
	{
		IPv6Address const& ipZero = IPv6Address::Zero;
		EXPECT_EQ(ipZero.toString(), "::");
		EXPECT_THAT(ipZero.toByteArray(), ::testing::Each(0));

		IPv6Address const& ipMulticastLower = IPv6Address::MulticastRangeLowerBound;
		EXPECT_EQ(ipMulticastLower.toString(), "ff00::");
		EXPECT_THAT(ipMulticastLower.toByteArray(),
		            ::testing::ElementsAre(0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                                   0x00, 0x00, 0x00));
	};

	TEST(IPv6AddressTest, IPv6AddressBasics)
	{
		IPv6Address ipDefault;
		EXPECT_EQ(ipDefault.toString(), "::");
		EXPECT_THAT(ipDefault.toByteArray(), ::testing::Each(0));

		IPv6Address ipString("2001:0db8:85a3:0000:0000:8a4e:0370:7334");
		EXPECT_EQ(ipString.toString(), "2001:db8:85a3::8a4e:370:7334");
		EXPECT_THAT(ipString.toByteArray(), ::testing::ElementsAre(0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00,
		                                                           0x00, 0x8A, 0x4E, 0x03, 0x70, 0x73, 0x34));

		EXPECT_THROW(IPv6Address("2001:0db8:85a3:0000:0000:8a4e:0370:7334:extra"), std::invalid_argument)
		    << "IPv6Address does not throw for out of bounds IP string.";
		EXPECT_THROW(IPv6Address("2001::ab01::c"), std::invalid_argument)
		    << "IPv6Address does not throw for multiple double colon in IP string.";
		EXPECT_THROW(IPv6Address("bogusString"), std::invalid_argument)
		    << "IPv6Address does not throw for non-IP string.";

		std::array<uint8_t, 16> ipArrayBuffer = { 0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00,
			                                      0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x34 };

		IPv6Address ipUint8Raw(ipArrayBuffer.data());
		EXPECT_EQ(ipUint8Raw.toString(), "2001:db8:85a3::8a2e:370:7334");
		EXPECT_THAT(ipUint8Raw.toByteArray(), ::testing::ElementsAre(0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00,
		                                                             0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x34));

		IPv6Address ipUint8Array(ipArrayBuffer);
		EXPECT_EQ(ipUint8Array.toString(), "2001:db8:85a3::8a2e:370:7334");
		EXPECT_THAT(ipUint8Array.toByteArray(), ::testing::ElementsAre(0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00,
		                                                               0x00, 0x00, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x34));

		EXPECT_TRUE(ipUint8Raw == ipUint8Array) << "Comparison operator '==' does not compare equal values correctly.";
		EXPECT_FALSE(ipUint8Raw == ipDefault) << "Comparison operator '==' does not compare unequal values correctly.";
		EXPECT_FALSE(ipUint8Raw != ipUint8Array) << "Comparison operator '!=' does not compare equal values correctly.";
		EXPECT_TRUE(ipUint8Raw != ipDefault) << "Comparison operator '!=' does not compare unequal values correctly.";

		EXPECT_TRUE(ipDefault < ipString) << "Comparison operator '<' does not compare less than values correctly.";
		EXPECT_FALSE(ipString < ipDefault) << "Comparison operator '<' does not compare less than values correctly.";

		std::array<uint8_t, 16> outBuffer = {};
		ipUint8Array.copyTo(outBuffer.data());
		EXPECT_EQ(ipUint8Array.toByteArray(), outBuffer);

		uint8_t* heapOutBuffer = nullptr;
		std::size_t heapOutBufferSize = 0;
		ipUint8Array.copyTo(&heapOutBuffer, heapOutBufferSize);

		ASSERT_NE(heapOutBuffer, nullptr);
		EXPECT_EQ(heapOutBufferSize, 16);
		EXPECT_TRUE(0 == std::memcmp(ipArrayBuffer.data(), heapOutBuffer, 16));
		delete[] heapOutBuffer;
	};

	TEST(IPv6AddressTest, Multicast)
	{
		IPv6Address underMulticastBound("fef0::");
		EXPECT_FALSE(underMulticastBound.isMulticast());

		IPv6Address atLowerMulticastBound("ff00::");
		EXPECT_TRUE(atLowerMulticastBound.isMulticast());

		IPv6Address inMulticastRange("ff00::ef");
		EXPECT_TRUE(inMulticastRange.isMulticast());
	};

	TEST(IPv6AddressTest, MatchNetwork)
	{
		FAIL() << "Not Implemented";
	};

	TEST(IPAddressTest, IPAddressBasics)
	{
		IPAddress ipDefault;
		EXPECT_EQ(ipDefault.getType(), IPAddress::AddressType::IPv4AddressType);
		EXPECT_EQ(ipDefault.getIPv4(), IPv4Address::Zero);
		EXPECT_TRUE(ipDefault.isZero());
		EXPECT_EQ(ipDefault.toString(), "0.0.0.0");

		IPAddress ip4String("192.168.0.1");
		EXPECT_EQ(ip4String.getType(), IPAddress::AddressType::IPv4AddressType);
		EXPECT_EQ(ip4String.getIPv4(), IPv4Address("192.168.0.1"));
		EXPECT_FALSE(ip4String.isZero());
		EXPECT_EQ(ip4String.toString(), "192.168.0.1");

		IPAddress ip6ZeroString("::");
		EXPECT_EQ(ip6ZeroString.getType(), IPAddress::AddressType::IPv6AddressType);
		EXPECT_EQ(ip6ZeroString.getIPv6(), IPv6Address::Zero);
		EXPECT_TRUE(ip6ZeroString.isZero());
		EXPECT_EQ(ip6ZeroString.toString(), "::");

		IPAddress ip6String("2001:db8:85a3::8a2e:370:7334");
		EXPECT_EQ(ip6String.getType(), IPAddress::AddressType::IPv6AddressType);
		EXPECT_EQ(ip6String.getIPv6(), IPv6Address("2001:db8:85a3::8a2e:370:7334"));
		EXPECT_FALSE(ip6String.isZero());
		EXPECT_EQ(ip6String.toString(), "2001:db8:85a3::8a2e:370:7334");

		EXPECT_THROW(IPAddress("192.168.300.1"), std::invalid_argument);
		EXPECT_THROW(IPAddress("2001:db8:85a3::8a2e:370:7334:extra"), std::invalid_argument)
		    << "IPAddress does not throw for out of bounds IP string.";
		EXPECT_THROW(IPv6Address("2001::ab01::c"), std::invalid_argument)
		    << "IPAddress does not throw for multiple double colon in IP string.";
		EXPECT_THROW(IPAddress("bogusString"), std::invalid_argument) << "IPAddress does not throw for non-IP string.";

		EXPECT_TRUE(ipDefault == IPv4Address::Zero) << "Comparison operator '==' does not compare equal values correctly.";
		EXPECT_FALSE(ipDefault != IPv4Address::Zero) << "Comparison operator '!=' does not compare equal values correctly.";

		EXPECT_FALSE(ipDefault == ip6ZeroString) << "Comparison operator '==' between IPv4 and IPv6 should always return false";
		EXPECT_TRUE(ipDefault != ip6ZeroString) << "Comparison operator '!=' between IPv4 and IPv6 should always return true";

		// Todo: less than operator
	};

	TEST(IPAddressTest, Multicast)
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
