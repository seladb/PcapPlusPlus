#include <array>
#include <cstring>
#include <sstream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "IpAddress.h"

namespace pcpp
{
	TEST(IPv4AddressTest, DefaultConstructor)
	{
		IPv4Address addr1;
		EXPECT_EQ(addr1.toString(), "0.0.0.0");
	}

	TEST(IPv4AddressTest, ConstructorWithInteger)
	{
        IPv4Address addr2(0x0100A8C0);  // 192.168.0.1
		EXPECT_EQ(addr2.toString(), "192.168.0.1");
	}

	TEST(IPv4AddressTest, ConstructorWithByteArray)
	{
		uint8_t bytes[4] = { 192, 168, 0, 1 };
		IPv4Address addr3(bytes);
		EXPECT_EQ(addr3.toString(), "192.168.0.1");
	}

	TEST(IPv4AddressTest, ConstructorWithStdArray)
	{
		std::array<uint8_t, 4> byteArray = { 192, 168, 0, 1 };
		IPv4Address addr4(byteArray);
		EXPECT_EQ(addr4.toString(), "192.168.0.1");
	}

	TEST(IPv4AddressTest, ConstructorWithString)
	{
		IPv4Address addr5("192.168.0.1");
		EXPECT_EQ(addr5.toString(), "192.168.0.1");
	}

	TEST(IPv4AddressTest, ToBytesMethod)
	{
		std::array<uint8_t, 4> bytes = { 192, 168, 0, 1 };
		IPv4Address addr5("192.168.0.1");
		const uint8_t* addrBytes = addr5.toBytes();
		EXPECT_EQ(memcmp(addrBytes, bytes.data(), 4), 0);
	}

	TEST(IPv4AddressTest, IsMulticastMethod)
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
	}

	TEST(IPv4AddressTest, EqualityOperator)
	{
		IPv4Address addr5("192.168.0.1");
		IPv4Address addr6("192.168.0.1");
		EXPECT_TRUE(addr5 == addr6);
		IPv4Address addr7("192.168.0.2");
		EXPECT_FALSE(addr5 == addr7);
	}

	TEST(IPv4AddressTest, LessThanOperator)
	{
		IPv4Address addr5("192.168.0.1");
		IPv4Address addr7("192.168.0.2");
		EXPECT_TRUE(addr5 < addr7);
		EXPECT_FALSE(addr7 < addr5);
	}

	TEST(IPv4AddressTest, MatchNetworkMethodWithIPv4Network)
	{
		IPv4Address addr5("192.168.0.1");
		IPv4Network network("192.168.0.0/24");
		EXPECT_TRUE(addr5.matchNetwork(network));
		
		IPv4Network network2("192.168.1.0/24");
		EXPECT_FALSE(addr5.matchNetwork(network2));

		IPv4Network network3("192.168.1.0/16");
		EXPECT_TRUE(addr5.matchNetwork(network3));
	}

	TEST(IPv4AddressTest, MatchNetworkMethodWithString)
	{
		IPv4Address addr5("192.168.0.1");
		EXPECT_TRUE(addr5.matchNetwork("192.168.0.0/24"));
		EXPECT_FALSE(addr5.matchNetwork("192.168.1.0/24"));
		EXPECT_TRUE(addr5.matchNetwork("192.168.1.0/16"));
	}

	TEST(IPv4AddressTest, IsValidIPv4AddressStaticMethod)
	{
		EXPECT_TRUE(IPv4Address::isValidIPv4Address("192.168.0.1"));
		EXPECT_FALSE(IPv4Address::isValidIPv4Address("999.999.999.999"));
		EXPECT_FALSE(IPv4Address::isValidIPv4Address("bogus string"));
	}

	TEST(IPv4AddressTest, OutputStreamOperator)
	{
		IPAddress ip("192.100.1.1");
		std::stringstream ss;
		ss << ip;
		EXPECT_EQ(ss.str(), "192.100.1.1");
	}

	TEST(IPv4AddressTest, ConstantHelpers)
	{
		EXPECT_EQ(IPv4Address::Zero.toString(), "0.0.0.0");
		EXPECT_EQ(IPv4Address::MulticastRangeLowerBound.toString(), "224.0.0.0");
		EXPECT_EQ(IPv4Address::MulticastRangeUpperBound.toString(), "239.255.255.255");
	};

	TEST(IPv4AddressTest, Literals)
	{
		using namespace pcpp::literals;

		IPv4Address ipString = "192.168.1.5"_ipv4;
		EXPECT_EQ(ipString.toInt(), 0x0501A8C0);
	}

	TEST(IPv6AddressTest, DefaultConstructor)
	{
		IPv6Address addr1;
		EXPECT_EQ(addr1.toString(), "::");
	}

	TEST(IPv6AddressTest, ConstructorWithByteArray)
	{
		uint8_t bytes[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
			                  0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 };
		IPv6Address addr2(bytes);
		EXPECT_EQ(addr2.toString(), "2001:db8:85a3::8a2e:370:7334");
	}

	TEST(IPv6AddressTest, ConstructorWithStdArray)
	{
		std::array<uint8_t, 16> byteArray = { 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
			                                  0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 };
		IPv6Address addr3(byteArray);
		EXPECT_EQ(addr3.toString(), "2001:db8:85a3::8a2e:370:7334");
	}

	TEST(IPv6AddressTest, ConstructorWithString)
	{
		IPv6Address addr4("2001:db8:85a3::8a2e:370:7334");
		EXPECT_EQ(addr4.toString(), "2001:db8:85a3::8a2e:370:7334");

		EXPECT_THROW(IPv6Address("2001:0db8:85a3:0000:0000:8a4e:0370:7334:extra"), std::invalid_argument)
		    << "IPv6Address does not throw for out of bounds IP string.";
		EXPECT_THROW(IPv6Address("2001::ab01::c"), std::invalid_argument)
		    << "IPv6Address does not throw for multiple double colon in IP string.";
		EXPECT_THROW(IPv6Address("bogusString"), std::invalid_argument)
		    << "IPv6Address does not throw for non-IP string.";
	}

	TEST(IPv6AddressTest, ToBytesMethod)
	{
		std::array<uint8_t, 16> bytes = { 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
			                  0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 };
		IPv6Address addr4("2001:db8:85a3::8a2e:370:7334");
		const uint8_t* addrBytes = addr4.toBytes();
		EXPECT_EQ(memcmp(addrBytes, bytes.data(), 16), 0);
	}

	TEST(IPv6AddressTest, IsMulticastMethod)
	{
		IPv6Address underMulticastBound("fef0::");
		EXPECT_FALSE(underMulticastBound.isMulticast());

		IPv6Address atLowerMulticastBound("ff00::");
		EXPECT_TRUE(atLowerMulticastBound.isMulticast());

		IPv6Address inMulticastRange("ff00::ef");
		EXPECT_TRUE(inMulticastRange.isMulticast());
	}

	TEST(IPv6AddressTest, EqualityOperator)
	{
		IPv6Address addr4("2001:db8:85a3::8a2e:370:7334");
		IPv6Address addr5("2001:db8:85a3::8a2e:370:7334");
		EXPECT_TRUE(addr4 == addr5);
		IPv6Address addr6("2001:db8:85a3::8a2e:370:7335");
		EXPECT_FALSE(addr4 == addr6);
	}

	TEST(IPv6AddressTest, LessThanOperator)
	{
		IPv6Address addr4("2001:db8:85a3::8a2e:370:7334");
		IPv6Address addr6("2001:db8:85a3::8a2e:370:7335");
		EXPECT_TRUE(addr4 < addr6);
		EXPECT_FALSE(addr6 < addr4);
	}

	TEST(IPv6AddressTest, MatchNetworkMethodWithIPv6Network)
	{
		IPv6Address addr4("2001:db8:85a3::8a2e:370:7334");
		IPv6Network network("2001:db8::/32");
		EXPECT_TRUE(addr4.matchNetwork(network));
		
		IPv6Network network2("2001:db9::/32");
		EXPECT_FALSE(addr4.matchNetwork(network2));
	}

	TEST(IPv6AddressTest, MatchNetworkMethodWithString)
	{
		IPv6Address addr4("2001:db8:85a3::8a2e:370:7334");
		EXPECT_TRUE(addr4.matchNetwork("2001:db8::/32"));
		EXPECT_FALSE(addr4.matchNetwork("2001:db9::/32"));
	}

	TEST(IPv6AddressTest, ConstantHelpers)
	{
		EXPECT_THAT(IPv6Address::Zero.toByteArray(), ::testing::Each(0));

		EXPECT_THAT(IPv6Address::MulticastRangeLowerBound.toByteArray(),
		            ::testing::ElementsAre(0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                                   0x00, 0x00, 0x00));
	};

	TEST(IPv6AddressTest, OutputStreamOperator)
	{
		IPv6Address ip("2001:db8:85a3::8a2e:370:7334");
		std::stringstream ss;
		ss << ip;
		EXPECT_EQ(ss.str(), "2001:db8:85a3::8a2e:370:7334");
	}

	TEST(IPv6AddressTest, Literals)
	{
		using namespace pcpp::literals;

		IPv6Address ipString = "2001:0db8:85a3:0000:0000:8a4e:0370:7334"_ipv6;
		EXPECT_THAT(ipString.toByteArray(), ::testing::ElementsAre(0x20, 0x01, 0x0D, 0xB8, 0x85, 0xA3, 0x00, 0x00, 0x00,
		                                                           0x00, 0x8A, 0x4E, 0x03, 0x70, 0x73, 0x34));
	}

	TEST(IPAddressTest, DefaultConstructor)
	{
		IPAddress ipDefault;
		EXPECT_EQ(ipDefault.getType(), IPAddress::AddressType::IPv4AddressType);
		EXPECT_EQ(ipDefault.getIPv4(), IPv4Address::Zero);
	}

	TEST(IPAddressTest, ConstructorWithIPv4Address)
	{
		IPv4Address ipv4Addr("192.168.0.1");
		IPAddress addr1(ipv4Addr);
		EXPECT_EQ(addr1.getType(), IPAddress::AddressType::IPv4AddressType);
		EXPECT_EQ(addr1.getIPv4(), ipv4Addr);
	}

	TEST(IPAddressTest, ConstructorWithIPv6Address)
	{
		IPv6Address ipv6Addr("2001:db8:85a3::8a2e:370:7334");
		IPAddress addr2(ipv6Addr);
		EXPECT_EQ(addr2.getType(), IPAddress::AddressType::IPv6AddressType);
		EXPECT_EQ(addr2.getIPv6(), ipv6Addr);
	}

	TEST(IPAddressTest, ConstructorWithString)
	{
		IPAddress ipv4String("192.168.0.1");
		EXPECT_EQ(ipv4String.getType(), IPAddress::AddressType::IPv4AddressType);
		EXPECT_EQ(ipv4String.getIPv4(), IPv4Address("192.168.0.1"));

		EXPECT_THROW(IPAddress("192.168.300.1"), std::invalid_argument);

		IPAddress ip6String("2001:db8:85a3::8a2e:370:7334");
		EXPECT_EQ(ip6String.getType(), IPAddress::AddressType::IPv6AddressType);
		EXPECT_EQ(ip6String.getIPv6(), IPv6Address("2001:db8:85a3::8a2e:370:7334"));

		EXPECT_THROW(IPAddress("2001:db8:85a3::8a2e:370:7334:extra"), std::invalid_argument);
		EXPECT_THROW(IPv6Address("2001::ab01::c"), std::invalid_argument);
		EXPECT_THROW(IPAddress("bogusString"), std::invalid_argument);
	}

	TEST(IPAddressTest, AssignmentOperatorWithIPv4Address)
	{
		IPv4Address ipv4Addr("192.168.0.1");
		IPAddress ipAddr;
		ASSERT_EQ(ipAddr.getType(), IPAddress::AddressType::IPv4AddressType);
		ASSERT_EQ(ipAddr.getIPv4(), IPv4Address::Zero);

		ipAddr = ipv4Addr;

		EXPECT_EQ(ipAddr.getType(), IPAddress::AddressType::IPv4AddressType);
		EXPECT_EQ(ipAddr.getIPv4(), ipv4Addr);
	}

	TEST(IPAddressTest, AssignmentOperatorWithIPv6Address)
	{
		IPv6Address ipv6Addr("2001:db8:85a3::8a2e:370:7334");
		IPAddress ipAddr;
		ASSERT_EQ(ipAddr.getType(), IPAddress::AddressType::IPv4AddressType);
		ASSERT_EQ(ipAddr.getIPv4(), IPv4Address::Zero);
		
		ipAddr = ipv6Addr;
		EXPECT_EQ(ipAddr.getType(), IPAddress::AddressType::IPv6AddressType);
		EXPECT_EQ(ipAddr.getIPv6(), ipv6Addr);
	}

	TEST(IPAddressTest, IsIPv4Method)
	{
		IPAddress ip4("192.168.0.1");
		EXPECT_TRUE(ip4.isIPv4());

		IPAddress ip6("2001:db8:85a3::8a2e:370:7334");
		EXPECT_FALSE(ip6.isIPv4());
	}

	TEST(IPAddressTest, IsIPv6Method)
	{
		IPAddress ip4("192.168.0.1");
		EXPECT_FALSE(ip4.isIPv6());

		IPAddress ip6("2001:db8:85a3::8a2e:370:7334");
		EXPECT_TRUE(ip6.isIPv6());
	}

	TEST(IPAddressTest, IsMulticastMethod)
	{
		using namespace pcpp::literals;

		{
			SCOPED_TRACE("IPv4");

			IPAddress underMulticastBound("223.0.0.0"_ipv4);
			EXPECT_FALSE(underMulticastBound.isMulticast());

			IPAddress atLowerMulticastBound("224.0.0.0"_ipv4);
			EXPECT_TRUE(atLowerMulticastBound.isMulticast());

			IPAddress inMulticastRange("230.9.4.1"_ipv4);
			EXPECT_TRUE(inMulticastRange.isMulticast());

			IPAddress atUpperMulticastBound("239.255.255.255"_ipv4);
			EXPECT_TRUE(atUpperMulticastBound.isMulticast());

			IPAddress overMulticastBound("240.0.0.0"_ipv4);
			EXPECT_FALSE(overMulticastBound.isMulticast());
		}

		{
			SCOPED_TRACE("IPv6");

			IPAddress underMulticastBound("fef0::"_ipv6);
			EXPECT_FALSE(underMulticastBound.isMulticast());

			IPAddress atLowerMulticastBound("ff00::"_ipv6);
			EXPECT_TRUE(atLowerMulticastBound.isMulticast());

			IPAddress inMulticastRange("ff00::ef"_ipv6);
			EXPECT_TRUE(inMulticastRange.isMulticast());
		}
	};

	TEST(IPAddressTest, OutputStreamOperrator)
	{
		IPAddress ip4("192.168.0.1");
		std::stringstream ss;
		ss << ip4;
		EXPECT_EQ(ss.str(), "192.168.0.1");

		IPAddress ip6("2001:db8:85a3::8a2e:370:7334");
		ss.str("");
		ss << ip6;
		EXPECT_EQ(ss.str(), "2001:db8:85a3::8a2e:370:7334");
	}

	TEST(IPv4NetworkTest, ConstructorWithSingleAddress)
	{
		using namespace pcpp::literals;

		IPv4Network netSingle("192.168.1.1"_ipv4);
		EXPECT_EQ(netSingle.getPrefixLen(), 32u);
		EXPECT_EQ(netSingle.getNetmask(), "255.255.255.255");
		EXPECT_EQ(netSingle.getNetworkPrefix(), "192.168.1.1"_ipv4);
		EXPECT_EQ(netSingle.getLowestAddress(), "192.168.1.1"_ipv4);
		EXPECT_EQ(netSingle.getHighestAddress(), "192.168.1.1"_ipv4);
		EXPECT_EQ(netSingle.getTotalAddressCount(), 1);
		EXPECT_EQ(netSingle.toString(), "192.168.1.1/32");
	}

	TEST(IPv4NetworkTest, ConstructorWithAddressAndPrefix)
	{
		using namespace pcpp::literals;
		
		IPv4Network netPrefix("192.168.1.1"_ipv4, 24u);
		EXPECT_EQ(netPrefix.getPrefixLen(), 24u);
		EXPECT_EQ(netPrefix.getNetmask(), "255.255.255.0");
		EXPECT_EQ(netPrefix.getNetworkPrefix(), "192.168.1.0"_ipv4);
		EXPECT_EQ(netPrefix.getLowestAddress(), "192.168.1.1"_ipv4);
		EXPECT_EQ(netPrefix.getHighestAddress(), "192.168.1.254"_ipv4);
		EXPECT_EQ(netPrefix.getTotalAddressCount(), 256);
		EXPECT_EQ(netPrefix.toString(), "192.168.1.0/24");
	}

	TEST(IPv4NetworkTest, ConstructorWithAddressAndNetmask)
	{
		using namespace pcpp::literals;

		IPv4Network netNetmask("192.168.1.1"_ipv4, "255.255.0.0");
		EXPECT_EQ(netNetmask.getPrefixLen(), 16u);
		EXPECT_EQ(netNetmask.getNetmask(), "255.255.0.0");
		EXPECT_EQ(netNetmask.getNetworkPrefix(), "192.168.0.0"_ipv4);
		EXPECT_EQ(netNetmask.getLowestAddress(), "192.168.0.1"_ipv4);
		EXPECT_EQ(netNetmask.getHighestAddress(), "192.168.255.254"_ipv4);
		EXPECT_EQ(netNetmask.getTotalAddressCount(), 256 * 256);
		EXPECT_EQ(netNetmask.toString(), "192.168.0.0/16");
	}

	TEST(IPv4NetworkTest, ConstructorWithString)
	{
		using namespace pcpp::literals;

		{
			SCOPED_TRACE("Valid c'tor: IPv4 address + prefix len");
			
			IPv4Network netStringWithPrefix("192.168.1.1/8");
			EXPECT_EQ(netStringWithPrefix.getPrefixLen(), 8u);
			EXPECT_EQ(netStringWithPrefix.getNetmask(), "255.0.0.0");
			EXPECT_EQ(netStringWithPrefix.getNetworkPrefix(), "192.0.0.0"_ipv4);
			EXPECT_EQ(netStringWithPrefix.getLowestAddress(), "192.0.0.1"_ipv4);
			EXPECT_EQ(netStringWithPrefix.getHighestAddress(), "192.255.255.254"_ipv4);
			EXPECT_EQ(netStringWithPrefix.getTotalAddressCount(), 256 * 256 * 256);
			EXPECT_EQ(netStringWithPrefix.toString(), "192.0.0.0/8");
		}

		{
			SCOPED_TRACE("Valid c'tor: IPv4 address + netmask");

			IPv4Network netStringWithMask("192.168.1.1/255.0.0.0");
			EXPECT_EQ(netStringWithMask.getPrefixLen(), 8u);
			EXPECT_EQ(netStringWithMask.getNetmask(), "255.0.0.0");
			EXPECT_EQ(netStringWithMask.getNetworkPrefix(), "192.0.0.0"_ipv4);
			EXPECT_EQ(netStringWithMask.getLowestAddress(), "192.0.0.1"_ipv4);
			EXPECT_EQ(netStringWithMask.getHighestAddress(), "192.255.255.254"_ipv4);
			EXPECT_EQ(netStringWithMask.getTotalAddressCount(), 256 * 256 * 256);
			EXPECT_EQ(netStringWithMask.toString(), "192.0.0.0/8");
		}
	}

	TEST(IPv4NetworkTest, IncludesMethod)
	{
		using namespace pcpp::literals;

		IPv4Network netBase("192.168.0.0/16");

		{
			SCOPED_TRACE("With single address");

			EXPECT_TRUE(netBase.includes("192.168.1.0"_ipv4));
			EXPECT_TRUE(netBase.includes("192.168.1.1"_ipv4));
			EXPECT_TRUE(netBase.includes("192.168.2.1"_ipv4));
			EXPECT_FALSE(netBase.includes("192.169.2.1"_ipv4));
		}
		
		{
			SCOPED_TRACE("With network");

			EXPECT_TRUE(netBase.includes(IPv4Network("192.168.1.0/24")));
			EXPECT_TRUE(netBase.includes(IPv4Network("192.168.2.0/24")));
			EXPECT_TRUE(netBase.includes(IPv4Network("192.168.0.0/16")));
			EXPECT_FALSE(netBase.includes(IPv4Network("192.0.0.0/8")));
		}
	};

	TEST(IPv4NetworkTest, OutputStreamOperator)
	{
		IPv4Network net("192.168.1.1/32");
		std::stringstream ss;
		ss << net;
		EXPECT_EQ(ss.str(), "192.168.1.1/32");
	}

	TEST(IPv6NetworkTest, ConstructorWithSingleAddress)
	{
		using namespace pcpp::literals;

		IPv6Network netSingle("2001:db8:85a3::8a2e:370:7334"_ipv6);
		EXPECT_EQ(netSingle.getPrefixLen(), 128u);
		EXPECT_EQ(netSingle.getNetmask(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		EXPECT_EQ(netSingle.getNetworkPrefix(), "2001:db8:85a3::8a2e:370:7334"_ipv6);
		EXPECT_EQ(netSingle.getLowestAddress(), "2001:db8:85a3::8a2e:370:7334"_ipv6);
		EXPECT_EQ(netSingle.getHighestAddress(), "2001:db8:85a3::8a2e:370:7334"_ipv6);
		EXPECT_EQ(netSingle.getTotalAddressCount(), 1);
		EXPECT_EQ(netSingle.toString(), "2001:db8:85a3::8a2e:370:7334/128");
	}

	TEST(IPv6NetworkTest, ConstructorWithAddressAndPrefix)
	{
		using namespace pcpp::literals;

		IPv6Network netPrefix("2001:db8:85a3::8a2e:370:7334"_ipv6, 96u);
		EXPECT_EQ(netPrefix.getPrefixLen(), 96u);
		EXPECT_EQ(netPrefix.getNetmask(), "ffff:ffff:ffff:ffff:ffff:ffff::");
		EXPECT_EQ(netPrefix.getNetworkPrefix(), "2001:db8:85a3::8a2e:0:0"_ipv6);
		EXPECT_EQ(netPrefix.getLowestAddress(), "2001:db8:85a3::8a2e:0:1"_ipv6);
		EXPECT_EQ(netPrefix.getHighestAddress(), "2001:db8:85a3::8a2e:ffff:ffff"_ipv6);
		EXPECT_EQ(netPrefix.getTotalAddressCount(), 4294967296ul);
		EXPECT_EQ(netPrefix.toString(), "2001:db8:85a3::8a2e:0:0/96");
	}

	TEST(IPv6NetworkTest, ConstructorWithAddressAndNetmask)
	{
		using namespace pcpp::literals;

		IPv6Network netNetmask("2001:db8:85a3::8a2e:370:7334"_ipv6, "ffff:ffff:ffff:ffff::");
		EXPECT_EQ(netNetmask.getPrefixLen(), 64u);
		EXPECT_EQ(netNetmask.getNetmask(), "ffff:ffff:ffff:ffff::");
		EXPECT_EQ(netNetmask.getNetworkPrefix(), "2001:db8:85a3::"_ipv6);
		EXPECT_EQ(netNetmask.getLowestAddress(), "2001:db8:85a3::1"_ipv6);
		EXPECT_EQ(netNetmask.getHighestAddress(), "2001:db8:85a3::ffff:ffff:ffff:ffff"_ipv6);
		EXPECT_THROW(netNetmask.getTotalAddressCount(), std::out_of_range);
		EXPECT_EQ(netNetmask.toString(), "2001:db8:85a3::/64");
	}

	TEST(IPv6NetworkTest, ConstructorWithString)
	{
		using namespace pcpp::literals;

		{
			SCOPED_TRACE("Valid c'tor: IPv6 address + prefix len");

			IPv6Network netStringWithPrefix("2001:db8:85a3::8a2e:370:7334/64");
			EXPECT_EQ(netStringWithPrefix.getPrefixLen(), 64u);
			EXPECT_EQ(netStringWithPrefix.getNetmask(), "ffff:ffff:ffff:ffff::");
			EXPECT_EQ(netStringWithPrefix.getNetworkPrefix(), "2001:db8:85a3::"_ipv6);
			EXPECT_EQ(netStringWithPrefix.getLowestAddress(), "2001:db8:85a3::1"_ipv6);
			EXPECT_EQ(netStringWithPrefix.getHighestAddress(), "2001:db8:85a3::ffff:ffff:ffff:ffff"_ipv6);
			EXPECT_THROW(netStringWithPrefix.getTotalAddressCount(), std::out_of_range);
			EXPECT_EQ(netStringWithPrefix.toString(), "2001:db8:85a3::/64");
		}

		{
			SCOPED_TRACE("Valid c'tor: IPv6 address + netmask");

			IPv6Network netStringWithMask("2001:db8:85a3::8a2e:370:7334/ffff:ffff:ffff:ffff::");
			EXPECT_EQ(netStringWithMask.getPrefixLen(), 64u);
			EXPECT_EQ(netStringWithMask.getNetmask(), "ffff:ffff:ffff:ffff::");
			EXPECT_EQ(netStringWithMask.getNetworkPrefix(), "2001:db8:85a3::"_ipv6);
			EXPECT_EQ(netStringWithMask.getLowestAddress(), "2001:db8:85a3::1"_ipv6);
			EXPECT_EQ(netStringWithMask.getHighestAddress(), "2001:db8:85a3::ffff:ffff:ffff:ffff"_ipv6);
			EXPECT_THROW(netStringWithMask.getTotalAddressCount(), std::out_of_range);
			EXPECT_EQ(netStringWithMask.toString(), "2001:db8:85a3::/64");
		}
	}
	TEST(IPv6NetworkTest, IncludesMethod)
	{
		using namespace pcpp::literals;

		IPv6Network netBase("2001:db8:85a3:34ac::/64");

		{
			SCOPED_TRACE("With single address");

			EXPECT_TRUE(netBase.includes("2001:db8:85a3:34ac::1"_ipv6));
			EXPECT_TRUE(netBase.includes("2001:db8:85a3:34ac:c::2"_ipv6));
			EXPECT_FALSE(netBase.includes("2001:db8:85a3:34ab::1"_ipv6));
		}

		{
			SCOPED_TRACE("With network");
			
			EXPECT_TRUE(netBase.includes(IPv6Network("2001:db8:85a3:34ac::/64")));
			EXPECT_TRUE(netBase.includes(IPv6Network("2001:db8:85a3:34ac::/72")));
			EXPECT_FALSE(netBase.includes(IPv6Network("2001:db8:85a3:34ac::/56")));
		}
	};

	TEST(IPv6NetworkTest, OutputStreamOperator)
	{
		using namespace pcpp::literals;

		IPv6Network net("2001:db8:85a3:34ac::/64");
		std::stringstream ss;
		ss << net;
		EXPECT_EQ(ss.str(), "2001:db8:85a3:34ac::/64");
	}

	TEST(IPNetworkTest, ConstructorWithSingleAddress)
	{
		using namespace pcpp::literals;

		{
			SCOPED_TRACE("IPv4 address");

			IPNetwork netSingleV4("192.168.1.1"_ipv4);
			EXPECT_TRUE(netSingleV4.isIPv4Network());
			EXPECT_FALSE(netSingleV4.isIPv6Network());
			EXPECT_EQ(netSingleV4.getPrefixLen(), 32u);
			EXPECT_EQ(netSingleV4.getNetmask(), "255.255.255.255");
			EXPECT_EQ(netSingleV4.getNetworkPrefix(), "192.168.1.1"_ipv4);
			EXPECT_EQ(netSingleV4.getLowestAddress(), "192.168.1.1"_ipv4);
			EXPECT_EQ(netSingleV4.getHighestAddress(), "192.168.1.1"_ipv4);
			EXPECT_EQ(netSingleV4.getTotalAddressCount(), 1);
			EXPECT_EQ(netSingleV4.toString(), "192.168.1.1/32");
		}
		{
			SCOPED_TRACE("IPv6 address");

			IPNetwork netSingleV6("2001:db8:85a3::8a2e:370:7334"_ipv6);
			EXPECT_FALSE(netSingleV6.isIPv4Network());
			EXPECT_TRUE(netSingleV6.isIPv6Network());
			EXPECT_EQ(netSingleV6.getPrefixLen(), 128u);
			EXPECT_EQ(netSingleV6.getNetmask(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
			EXPECT_EQ(netSingleV6.getNetworkPrefix(), "2001:db8:85a3::8a2e:370:7334"_ipv6);
			EXPECT_EQ(netSingleV6.getLowestAddress(), "2001:db8:85a3::8a2e:370:7334"_ipv6);
			EXPECT_EQ(netSingleV6.getHighestAddress(), "2001:db8:85a3::8a2e:370:7334"_ipv6);
			EXPECT_EQ(netSingleV6.getTotalAddressCount(), 1);
			EXPECT_EQ(netSingleV6.toString(), "2001:db8:85a3::8a2e:370:7334/128");
		}
	}

	TEST(IPNetworkTest, ConstructorWithAddressAndPrefix)
	{
		using namespace pcpp::literals;

		{
			SCOPED_TRACE("IPv4 address");

			IPNetwork netPrefix("192.168.1.1"_ipv4, 24u);
			EXPECT_EQ(netPrefix.getPrefixLen(), 24u);
			EXPECT_EQ(netPrefix.getNetmask(), "255.255.255.0");
			EXPECT_EQ(netPrefix.getNetworkPrefix(), "192.168.1.0"_ipv4);
			EXPECT_EQ(netPrefix.getLowestAddress(), "192.168.1.1"_ipv4);
			EXPECT_EQ(netPrefix.getHighestAddress(), "192.168.1.254"_ipv4);
			EXPECT_EQ(netPrefix.getTotalAddressCount(), 256);
			EXPECT_EQ(netPrefix.toString(), "192.168.1.0/24");
		}

		{
			SCOPED_TRACE("IPv6 address");

			IPNetwork netPrefix("2001:db8:85a3::8a2e:370:7334"_ipv6, 96u);
			EXPECT_EQ(netPrefix.getPrefixLen(), 96u);
			EXPECT_EQ(netPrefix.getNetmask(), "ffff:ffff:ffff:ffff:ffff:ffff::");
			EXPECT_EQ(netPrefix.getNetworkPrefix(), "2001:db8:85a3::8a2e:0:0"_ipv6);
			EXPECT_EQ(netPrefix.getLowestAddress(), "2001:db8:85a3::8a2e:0:1"_ipv6);
			EXPECT_EQ(netPrefix.getHighestAddress(), "2001:db8:85a3::8a2e:ffff:ffff"_ipv6);
			EXPECT_EQ(netPrefix.getTotalAddressCount(), 4294967296ul);
			EXPECT_EQ(netPrefix.toString(), "2001:db8:85a3::8a2e:0:0/96");
		}
	}
	
	TEST(IPNetworkTest, ConstructorWithAddressAndNetmask)
	{
		using namespace pcpp::literals;

		{
			SCOPED_TRACE("IPv4 address");

			IPNetwork netNetmask("192.168.1.1"_ipv4, "255.255.0.0");
			EXPECT_EQ(netNetmask.getPrefixLen(), 16u);
			EXPECT_EQ(netNetmask.getNetmask(), "255.255.0.0");
			EXPECT_EQ(netNetmask.getNetworkPrefix(), "192.168.0.0"_ipv4);
			EXPECT_EQ(netNetmask.getLowestAddress(), "192.168.0.1"_ipv4);
			EXPECT_EQ(netNetmask.getHighestAddress(), "192.168.255.254"_ipv4);
			EXPECT_EQ(netNetmask.getTotalAddressCount(), 256 * 256);
			EXPECT_EQ(netNetmask.toString(), "192.168.0.0/16");
		}

		{
			SCOPED_TRACE("IPv6 address");

			IPNetwork netNetmask("2001:db8:85a3::8a2e:370:7334"_ipv6, "ffff:ffff:ffff:ffff::");
			EXPECT_EQ(netNetmask.getPrefixLen(), 64u);
			EXPECT_EQ(netNetmask.getNetmask(), "ffff:ffff:ffff:ffff::");
			EXPECT_EQ(netNetmask.getNetworkPrefix(), "2001:db8:85a3::"_ipv6);
			EXPECT_EQ(netNetmask.getLowestAddress(), "2001:db8:85a3::1"_ipv6);
			EXPECT_EQ(netNetmask.getHighestAddress(), "2001:db8:85a3::ffff:ffff:ffff:ffff"_ipv6);
			EXPECT_THROW(netNetmask.getTotalAddressCount(), std::out_of_range);
			EXPECT_EQ(netNetmask.toString(), "2001:db8:85a3::/64");
		}
	}

	TEST(IPNetworkTest, IncludesMethodWithIPv4)
	{
		using namespace pcpp::literals;

		IPNetwork netBaseV4("192.168.0.0/16");
		EXPECT_TRUE(netBaseV4.includes("192.168.1.0"_ipv4));
		EXPECT_TRUE(netBaseV4.includes("192.168.1.1"_ipv4));
		EXPECT_TRUE(netBaseV4.includes("192.168.2.1"_ipv4));
		EXPECT_FALSE(netBaseV4.includes("192.169.2.1"_ipv4));
		EXPECT_FALSE(netBaseV4.includes("2001:db8:85a3:34ac::"_ipv6));
		EXPECT_FALSE(netBaseV4.includes("::C0A9:0201"_ipv6)) << "IPNetwork in V4 mode should not match V6 equivalents.";

		EXPECT_TRUE(netBaseV4.includes(IPNetwork("192.168.1.0/24")));
		EXPECT_TRUE(netBaseV4.includes(IPNetwork("192.168.2.0/24")));
		EXPECT_TRUE(netBaseV4.includes(IPNetwork("192.168.0.0/16")));
		EXPECT_FALSE(netBaseV4.includes(IPNetwork("192.0.0.0/8")));
		EXPECT_FALSE(netBaseV4.includes(IPNetwork("2001:db8:85a3:34ac::/64")));
		EXPECT_FALSE(netBaseV4.includes(IPNetwork("::c0a9:0000/112")))
		    << "IPNetwork in V4 mode should not match V6 equivalents.";
		EXPECT_FALSE(netBaseV4.includes(IPNetwork("::c0a9:0201/116")))
		    << "IPNetwork in V4 mode should not match V6 equivalents.";
	}

	TEST(IPNetworkTest, IncludesMethodWithIPv6)
	{
		using namespace pcpp::literals;

		IPNetwork netBaseV6("2001:db8:85a3:34ac::/64");
		EXPECT_TRUE(netBaseV6.includes("2001:db8:85a3:34ac::1"_ipv6));
		EXPECT_TRUE(netBaseV6.includes("2001:db8:85a3:34ac:c::2"_ipv6));
		EXPECT_FALSE(netBaseV6.includes("2001:db8:85a3:34ab::1"_ipv6));

		EXPECT_TRUE(netBaseV6.includes(IPNetwork("2001:db8:85a3:34ac::/64")));
		EXPECT_TRUE(netBaseV6.includes(IPNetwork("2001:db8:85a3:34ac::/72")));
		EXPECT_FALSE(netBaseV6.includes(IPNetwork("2001:db8:85a3:34ac::/56")));

		IPNetwork netBaseV6_V4compat("::c0a8:0000/112");
		EXPECT_FALSE(netBaseV6_V4compat.includes("192.168.1.0"_ipv4))
		    << "IPNetwork in V6 mode should not match V4 equivalent ranges.";
		EXPECT_FALSE(netBaseV6_V4compat.includes("192.168.2.1"_ipv4))
		    << "IPNetwork in V6 mode should not match V4 equivalent ranges.";
		EXPECT_FALSE(netBaseV6_V4compat.includes("192.169.2.1"_ipv4))
		    << "IPNetwork in V6 mode should not match V4 equivalent ranges.";

		EXPECT_FALSE(netBaseV6_V4compat.includes(IPNetwork("192.169.1.1/15")))
		    << "IPNetwork in V6 mode should not match V4 equivalent ranges.";
		EXPECT_FALSE(netBaseV6_V4compat.includes(IPNetwork("192.169.1.1/16")))
		    << "IPNetwork in V6 mode should not match V4 equivalent ranges.";
		EXPECT_FALSE(netBaseV6_V4compat.includes(IPNetwork("192.169.1.1/17")))
		    << "IPNetwork in V6 mode should not match V4 equivalent ranges.";
	}

	TEST(IPNetworkTest, OutputStreamOperator)
	{
		IPv4Network netV4("192.168.1.1/32");
		std::stringstream ss;
		ss << netV4;
		EXPECT_EQ(ss.str(), "192.168.1.1/32");

		ss.str("");
		IPNetwork netV6("2001:db8:85a3:34ac::/64");
		ss << netV6;
		EXPECT_EQ(ss.str(), "2001:db8:85a3:34ac::/64");
	}
}  // namespace pcpp
