#include "../TestDefinition.h"
#include "../Common/TestUtils.h"
#include "../Common/GlobalTestArgs.h"
#include <sstream>
#include <algorithm>
#include <cmath>
#include <tuple>
#include "EndianPortable.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include "IpUtils.h"
#include "IpAddress.h"
#include "IpAddressUtils.h"
#include "MacAddress.h"
#include "LRUList.h"
#include "NetworkUtils.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

extern PcapTestArgs PcapTestGlobalArgs;

PTF_TEST_CASE(TestIPAddress)
{
	pcpp::IPAddress ip4Addr = pcpp::IPAddress("10.0.0.4");
	PTF_ASSERT_EQUAL(ip4Addr.getType(), pcpp::IPAddress::IPv4AddressType, enum);
	PTF_ASSERT_EQUAL(ip4Addr.toString(), "10.0.0.4");
	{
		std::ostringstream oss;
		oss << ip4Addr;
		PTF_ASSERT_EQUAL(oss.str(), "10.0.0.4");
	}
	pcpp::IPv4Address ip4AddrFromIpAddr = ip4Addr.getIPv4();
	{
		std::ostringstream oss;
		oss << ip4AddrFromIpAddr;
		PTF_ASSERT_EQUAL(oss.str(), "10.0.0.4");
	}
	PTF_ASSERT_EQUAL(ip4AddrFromIpAddr.toInt(), htobe32(0x0A000004));
	pcpp::IPv4Address secondIPv4Address(std::string("1.1.1.1"));
	secondIPv4Address = ip4AddrFromIpAddr;
	PTF_ASSERT_EQUAL(ip4AddrFromIpAddr, secondIPv4Address);

	{
		in_addr inAddr_v4;
		PTF_ASSERT_EQUAL(inet_pton(AF_INET, "10.0.0.4", &inAddr_v4), 1);

		// Equality between equal in_addr and IPv4Address.
		PTF_ASSERT_TRUE(ip4AddrFromIpAddr == inAddr_v4);
		PTF_ASSERT_TRUE(inAddr_v4 == ip4AddrFromIpAddr);
		PTF_ASSERT_FALSE(ip4AddrFromIpAddr != inAddr_v4);
		PTF_ASSERT_FALSE(inAddr_v4 != ip4AddrFromIpAddr);

		// Equality between equal in_addr and IPAddress.
		PTF_ASSERT_TRUE(ip4Addr == inAddr_v4);
		PTF_ASSERT_TRUE(inAddr_v4 == ip4Addr);
		PTF_ASSERT_FALSE(ip4Addr != inAddr_v4);
		PTF_ASSERT_FALSE(inAddr_v4 != ip4Addr);

		PTF_ASSERT_EQUAL(inet_pton(AF_INET, "10.0.1.4", &inAddr_v4), 1);
		// Equality between different in_addr and IPv4Address.
		PTF_ASSERT_FALSE(ip4AddrFromIpAddr == inAddr_v4);
		PTF_ASSERT_FALSE(inAddr_v4 == ip4AddrFromIpAddr);
		PTF_ASSERT_TRUE(ip4AddrFromIpAddr != inAddr_v4);
		PTF_ASSERT_TRUE(inAddr_v4 != ip4AddrFromIpAddr);

		// Equality between different in_addr and IPAddress.
		PTF_ASSERT_FALSE(ip4Addr == inAddr_v4);
		PTF_ASSERT_FALSE(inAddr_v4 == ip4Addr);
		PTF_ASSERT_TRUE(ip4Addr != inAddr_v4);
		PTF_ASSERT_TRUE(inAddr_v4 != ip4Addr);
	}

	// networks
	pcpp::IPv4Address ipv4Addr("10.0.0.4");
	auto networks = std::vector<std::tuple<std::string, std::string, std::string>>{
		std::tuple<std::string, std::string, std::string>{ "10.8.0.0", "8",  "255.0.0.0"     },
		std::tuple<std::string, std::string, std::string>{ "10.0.0.0", "24", "255.255.255.0" }
	};
	for (const auto& network : networks)
	{
		std::string networkWithPrefixAsString = std::get<0>(network) + "/" + std::get<1>(network);
		std::string networkWithMaskAsString = std::get<0>(network) + "/" + std::get<2>(network);
		PTF_ASSERT_TRUE(ipv4Addr.matchNetwork(networkWithPrefixAsString));
		PTF_ASSERT_TRUE(ipv4Addr.matchNetwork(networkWithMaskAsString));
		PTF_ASSERT_TRUE(ipv4Addr.matchNetwork(pcpp::IPv4Network(networkWithPrefixAsString)));
	}

	pcpp::Logger::getInstance().suppressLogs();
	auto invalidMasks = std::vector<std::string>{ "aaaa",        "10.0.0.0",       "10.0.0.0/aa",
		                                          "10.0.0.0/33", "999.999.1.1/24", "10.10.10.10/99.99.99" };
	for (const auto& invalidMask : invalidMasks)
	{
		PTF_ASSERT_FALSE(ipv4Addr.matchNetwork(invalidMask));
	}
	pcpp::Logger::getInstance().enableLogs();

	PTF_ASSERT_RAISES(pcpp::IPv4Address("invalid"), std::invalid_argument, "Not a valid IPv4 address: invalid");
	PTF_ASSERT_RAISES(pcpp::IPv4Address("321.123.1000.1"), std::invalid_argument,
	                  "Not a valid IPv4 address: 321.123.1000.1");

	std::string ip6AddrString("2607:f0d0:1002:51::4");
	pcpp::IPAddress ip6Addr = pcpp::IPAddress(ip6AddrString);
	PTF_ASSERT_EQUAL(ip6Addr.getType(), pcpp::IPAddress::IPv6AddressType, enum);
	PTF_ASSERT_EQUAL(ip6Addr.toString(), "2607:f0d0:1002:51::4");
	{
		std::ostringstream oss;
		oss << ip6Addr;
		PTF_ASSERT_EQUAL(oss.str(), "2607:f0d0:1002:51::4");
	}
	pcpp::IPv6Address ip6AddrFromIpAddr = ip6Addr.getIPv6();
	{
		std::ostringstream oss;
		oss << ip6AddrFromIpAddr;
		PTF_ASSERT_EQUAL(oss.str(), "2607:f0d0:1002:51::4");
	}
	uint8_t addrAsByteArray[16];
	ip6AddrFromIpAddr.copyTo(addrAsByteArray);
	uint8_t expectedByteArray[16] = { 0x26, 0x07, 0xF0, 0xD0, 0x10, 0x02, 0x00, 0x51,
		                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 };
	for (int i = 0; i < 16; i++)
	{
		PTF_ASSERT_EQUAL(addrAsByteArray[i], expectedByteArray[i]);
	}

	{
		in6_addr in_ipv6_addr;
		PTF_ASSERT_EQUAL(inet_pton(AF_INET6, "2607:f0d0:1002:51::4", &in_ipv6_addr), 1);

		// Equality between equal in6_addr and IPv6Address.
		PTF_ASSERT_TRUE(ip6AddrFromIpAddr == in_ipv6_addr);
		PTF_ASSERT_TRUE(in_ipv6_addr == ip6AddrFromIpAddr);
		PTF_ASSERT_FALSE(ip6AddrFromIpAddr != in_ipv6_addr);
		PTF_ASSERT_FALSE(in_ipv6_addr != ip6AddrFromIpAddr);

		// Equality between equal in6_addr and IPAddress.
		PTF_ASSERT_TRUE(ip6Addr == in_ipv6_addr);
		PTF_ASSERT_TRUE(in_ipv6_addr == ip6Addr);
		PTF_ASSERT_FALSE(ip6Addr != in_ipv6_addr);
		PTF_ASSERT_FALSE(in_ipv6_addr != ip6Addr);

		PTF_ASSERT_EQUAL(inet_pton(AF_INET6, "2607:f0d0:1002:51:4::4", &in_ipv6_addr), 1);
		PTF_ASSERT_FALSE(ip6AddrFromIpAddr == in_ipv6_addr);
		PTF_ASSERT_FALSE(in_ipv6_addr == ip6AddrFromIpAddr);
		PTF_ASSERT_TRUE(ip6AddrFromIpAddr != in_ipv6_addr);
		PTF_ASSERT_TRUE(in_ipv6_addr != ip6AddrFromIpAddr);

		// Equality between different in6_addr and IPAddress.
		PTF_ASSERT_FALSE(ip6Addr == in_ipv6_addr);
		PTF_ASSERT_FALSE(in_ipv6_addr == ip6Addr);
		PTF_ASSERT_TRUE(ip6Addr != in_ipv6_addr);
		PTF_ASSERT_TRUE(in_ipv6_addr != ip6Addr);
	}

	ip6Addr = pcpp::IPAddress("2607:f0d0:1002:0051:0000:0000:0000:0004");
	PTF_ASSERT_EQUAL(ip6Addr.getType(), pcpp::IPAddress::IPv6AddressType, enum);
	PTF_ASSERT_EQUAL(ip6Addr.toString(), "2607:f0d0:1002:51::4");
	pcpp::IPv6Address secondIPv6Address(std::string("2607:f0d0:1002:52::5"));
	ip6AddrFromIpAddr = ip6Addr.getIPv6();
	secondIPv6Address = ip6AddrFromIpAddr;
	PTF_ASSERT_EQUAL(ip6AddrFromIpAddr, secondIPv6Address);

	PTF_ASSERT_RAISES(pcpp::IPv6Address("invalid"), std::invalid_argument, "Not a valid IPv6 address: invalid");
	PTF_ASSERT_RAISES(pcpp::IPv6Address("zzzz:2222:1002:0051:0000:0000:0000:0004"), std::invalid_argument,
	                  "Not a valid IPv6 address: zzzz:2222:1002:0051:0000:0000:0000:0004");

	// networks
	pcpp::IPv6Address ip6Addr2("2607:f0d0:1002:0051:ffff::0004");
	pcpp::IPv6Address ipv6NetworkPrefix("2607:f0d0:1002:0051:fffe::");
	auto ipv6Networks = std::vector<std::tuple<uint8_t, std::string, std::string>>{
		std::tuple<uint8_t, std::string, std::string>{ 64, "64", "ffff:ffff:ffff:ffff::"      },
		std::tuple<uint8_t, std::string, std::string>{ 32, "32", "ffff:ffff::"                },
		std::tuple<uint8_t, std::string, std::string>{ 79, "79", "ffff:ffff:ffff:ffff:fffe::" },
		std::tuple<uint8_t, std::string, std::string>{ 0,  "0",  "::"                         }
	};

	for (const auto& ipv6Network : ipv6Networks)
	{
		PTF_ASSERT_TRUE(ip6Addr2.matchNetwork(pcpp::IPv6Network(ipv6NetworkPrefix, std::get<0>(ipv6Network))));

		std::string networkWithPrefixAsString = ipv6NetworkPrefix.toString() + "/" + std::get<1>(ipv6Network);
		std::string networkWithMaskAsString = ipv6NetworkPrefix.toString() + "/" + std::get<2>(ipv6Network);
		PTF_ASSERT_TRUE(ip6Addr2.matchNetwork(networkWithPrefixAsString));
		PTF_ASSERT_TRUE(ip6Addr2.matchNetwork(networkWithMaskAsString));
	}

	auto ipv6NetworksNotMatch = std::vector<std::tuple<uint8_t, std::string, std::string>>{
		std::tuple<uint8_t, std::string, std::string>{ 80,  "80",  "ffff:ffff:ffff:ffff:ffff::"              },
		std::tuple<uint8_t, std::string, std::string>{ 128, "128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" }
	};

	for (const auto& ipv6Network : ipv6NetworksNotMatch)
	{
		PTF_ASSERT_FALSE(ip6Addr2.matchNetwork(pcpp::IPv6Network(ipv6NetworkPrefix, std::get<0>(ipv6Network))));

		std::string networkWithPrefixAsString = ipv6NetworkPrefix.toString() + "/" + std::get<1>(ipv6Network);
		std::string networkWithMaskAsString = ipv6NetworkPrefix.toString() + "/" + std::get<2>(ipv6Network);
		PTF_ASSERT_FALSE(ip6Addr2.matchNetwork(networkWithPrefixAsString));
		PTF_ASSERT_FALSE(ip6Addr2.matchNetwork(networkWithMaskAsString));
	}

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(ip6Addr2.matchNetwork("invalid"));
	PTF_ASSERT_FALSE(ip6Addr2.matchNetwork("10.8.0.0/16"));
	pcpp::Logger::getInstance().enableLogs();

	// Test less-than comparison operator
	pcpp::IPv4Address IpV4_1("1.1.1.1");
	pcpp::IPv4Address IpV4_2("212.0.0.1");
	pcpp::IPv4Address IpV4_3("224.0.0.0");
	pcpp::IPv4Address IpV4_4("224.0.0.0");

	PTF_ASSERT_TRUE(IpV4_1 < IpV4_2);
	PTF_ASSERT_TRUE(IpV4_1 < IpV4_3);
	PTF_ASSERT_TRUE(IpV4_2 < IpV4_3);
	PTF_ASSERT_FALSE(IpV4_3 < IpV4_4);

	pcpp::IPv6Address ipv6Address("2001:db8::2:1");
	pcpp::IPv6Address ipv6AddressLong("2001:db8:0:0:0:0:2:1");
	pcpp::IPv6Address ipv6Address2("2001:db8::2:2");

	PTF_ASSERT_FALSE(ipv6Address < ipv6AddressLong);
	PTF_ASSERT_TRUE(ipv6Address < ipv6Address2);

	pcpp::IPAddress baseIpv4_1("1.1.1.1");
	pcpp::IPAddress baseIpv4_2("1.1.1.2");
	pcpp::IPAddress baseIPv6_1("2001:db8::2:1");
	pcpp::IPAddress baseIPv6_2("2001:db8::2:2");

	// Compare IPv4 against IPv4
	PTF_ASSERT_TRUE(baseIpv4_1 < baseIpv4_2);
	PTF_ASSERT_FALSE(baseIpv4_2 < baseIpv4_1);

	// Compare IPv6 against IPv6
	PTF_ASSERT_TRUE(baseIPv6_1 < baseIPv6_2);
	PTF_ASSERT_FALSE(baseIPv6_2 < baseIPv6_1);

	// Compare IPv6 against IPv4
	PTF_ASSERT_TRUE(baseIpv4_1 < baseIPv6_1);
	PTF_ASSERT_TRUE(baseIpv4_1 < baseIPv6_2);
	PTF_ASSERT_TRUE(baseIpv4_2 < baseIPv6_1);
	PTF_ASSERT_TRUE(baseIpv4_2 < baseIPv6_2);

	// Compare IPv4 against IPv6
	PTF_ASSERT_FALSE(baseIPv6_1 < baseIpv4_1);
	PTF_ASSERT_FALSE(baseIPv6_2 < baseIpv4_1);
	PTF_ASSERT_FALSE(baseIPv6_1 < baseIpv4_2);
	PTF_ASSERT_FALSE(baseIPv6_2 < baseIpv4_2);
}  // TestIPAddress

PTF_TEST_CASE(TestMacAddress)
{
	pcpp::MacAddress macAddr1(0x11, 0x2, 0x33, 0x4, 0x55, 0x6);
	pcpp::MacAddress macAddr2(0x11, 0x2, 0x33, 0x4, 0x55, 0x6);
	PTF_ASSERT_EQUAL(macAddr1, macAddr2);

	pcpp::MacAddress macAddr3(std::string("11:02:33:04:55:06"));
	PTF_ASSERT_EQUAL(macAddr1, macAddr3);

	uint8_t addrAsArr[6] = { 0x11, 0x2, 0x33, 0x4, 0x55, 0x6 };
	pcpp::MacAddress macAddr4(addrAsArr);
	PTF_ASSERT_EQUAL(macAddr1, macAddr4);

	// verify if some one try to use char[6] or char* to express MAC address in bytes
	char invalidCharArrayAddress[6] = { 0x11, 0x2, 0x33, 0x4, 0x55, 0x6 };
	PTF_ASSERT_RAISES(pcpp::MacAddress{ invalidCharArrayAddress }, std::invalid_argument,
	                  "Invalid MAC address format, should be xx:xx:xx:xx:xx:xx");

	PTF_ASSERT_EQUAL(macAddr1.toString(), "11:02:33:04:55:06");
	std::ostringstream oss;
	oss << macAddr1;
	PTF_ASSERT_EQUAL(oss.str(), "11:02:33:04:55:06");

	uint8_t* arrToCopyTo = nullptr;
	macAddr3.copyTo(&arrToCopyTo);
	PTF_ASSERT_EQUAL(arrToCopyTo[0], 0x11, hex);
	PTF_ASSERT_EQUAL(arrToCopyTo[1], 0x02, hex);
	PTF_ASSERT_EQUAL(arrToCopyTo[2], 0x33, hex);
	PTF_ASSERT_EQUAL(arrToCopyTo[3], 0x04, hex);
	PTF_ASSERT_EQUAL(arrToCopyTo[4], 0x55, hex);
	PTF_ASSERT_EQUAL(arrToCopyTo[5], 0x06, hex);
	delete[] arrToCopyTo;

	uint8_t macBytes[6];
	macAddr3.copyTo(macBytes);
	PTF_ASSERT_BUF_COMPARE(macBytes, addrAsArr, 6);

#if __cplusplus > 199711L || _MSC_VER >= 1800
	pcpp::MacAddress macCpp11Valid{ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB };
	PTF_ASSERT_RAISES(pcpp::MacAddress({ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB }), std::invalid_argument,
	                  "Invalid initializer list size, should be 6");
#endif

	pcpp::MacAddress mac6(macAddr1);
	PTF_ASSERT_EQUAL(mac6, macAddr1);
	mac6 = macAddr2;
	PTF_ASSERT_EQUAL(mac6, macAddr2);

	pcpp::MacAddress macWithZero("aa:aa:00:aa:00:aa");  // valid
	PTF_ASSERT_RAISES(pcpp::MacAddress("aa:aa:aa:aa:aa:aa:bb:bb:bb:bb"), std::invalid_argument,
	                  "Invalid MAC address format, should be xx:xx:xx:xx:xx:xx");
	PTF_ASSERT_RAISES(pcpp::MacAddress("aa:aa:aa"), std::invalid_argument,
	                  "Invalid MAC address format, should be xx:xx:xx:xx:xx:xx");
	PTF_ASSERT_RAISES(pcpp::MacAddress("aa:aa:aa:ZZ:aa:aa"), std::invalid_argument,
	                  "Invalid MAC address format, should be xx:xx:xx:xx:xx:xx");
	PTF_ASSERT_RAISES(pcpp::MacAddress("aa:aa:aa:aa:aa:aa:"), std::invalid_argument,
	                  "Invalid MAC address format, should be xx:xx:xx:xx:xx:xx");
}  // TestMacAddress

PTF_TEST_CASE(TestLRUList)
{
	pcpp::LRUList<uint32_t> lruList(2);

	uint32_t deletedValue = 0;
	PTF_ASSERT_EQUAL(lruList.put(1, &deletedValue), 0);
	PTF_ASSERT_EQUAL(deletedValue, 0);

	PTF_ASSERT_EQUAL(lruList.put(2, nullptr), 0);

	PTF_ASSERT_EQUAL(lruList.put(3, &deletedValue), 1);
	PTF_ASSERT_EQUAL(deletedValue, 1);

	lruList.eraseElement(1);
	lruList.eraseElement(2);
	lruList.eraseElement(3);
	PTF_ASSERT_EQUAL(lruList.getSize(), 0);
}  // TestLRUList

PTF_TEST_CASE(TestGeneralUtils)
{
	uint8_t resultArr[4];
	const uint8_t expectedBytes[] = { 0xaa, 0xbb };
	size_t result = pcpp::hexStringToByteArray("AABB", resultArr, sizeof(resultArr));
	PTF_ASSERT_TRUE(result > 0);
	PTF_ASSERT_TRUE(result <= sizeof(resultArr));
	PTF_ASSERT_BUF_COMPARE(resultArr, expectedBytes, result);

	pcpp::Logger::getInstance().suppressLogs();
	// odd length
	result = pcpp::hexStringToByteArray("aab", resultArr, sizeof(resultArr));
	PTF_ASSERT_EQUAL(result, 0);
	// wrong input
	result = pcpp::hexStringToByteArray("zzvv", resultArr, sizeof(resultArr));
	PTF_ASSERT_EQUAL(result, 0);
	PTF_ASSERT_EQUAL(resultArr[0], '\0', ptr);
	pcpp::Logger::getInstance().enableLogs();

	// short buffer
	const uint8_t expectedBytes2[] = { 0x01, 0x02, 0x03, 0x04 };
	result = pcpp::hexStringToByteArray("0102030405", resultArr, sizeof(resultArr));
	PTF_ASSERT_EQUAL(result, 4);
	PTF_ASSERT_BUF_COMPARE(resultArr, expectedBytes2, result);
}  // TestGeneralUtils

PTF_TEST_CASE(TestGetMacAddress)
{
	pcpp::PcapLiveDevice* liveDev = nullptr;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);

	// fetch all IP addresses from arp table
	std::string ipsInArpTableAsString;
#ifdef _WIN32
	ipsInArpTableAsString =
	    pcpp::executeShellCommand(R"(arp -a | for /f "tokens=1" %i in ('findstr dynamic') do @echo %i)");
	ipsInArpTableAsString.erase(std::remove(ipsInArpTableAsString.begin(), ipsInArpTableAsString.end(), ' '),
	                            ipsInArpTableAsString.end());
#else
	ipsInArpTableAsString = pcpp::executeShellCommand("arp -a | awk '{print $2}' | sed 's/.$//; s/^.//'");
#endif

	PTF_ASSERT_NOT_EQUAL(ipsInArpTableAsString, "");

	// iterate all IP addresses and arping each one until one of them answers
	pcpp::MacAddress result = pcpp::MacAddress::Zero;
	std::stringstream sstream(ipsInArpTableAsString);
	std::string ip;
	double time = -1;
	bool foundValidIpAddr = false;
	while (std::getline(sstream, ip, '\n'))
	{
		pcpp::IPv4Address ipAddr;
		try
		{
			ipAddr = pcpp::IPv4Address(ip);
		}
		catch (const std::exception&)
		{
			continue;
		}

		if (ipAddr == liveDev->getIPv4Address())
			continue;

		foundValidIpAddr = true;
		pcpp::Logger::getInstance().suppressLogs();

		for (int i = 0; i < 3; i++)
		{
			result = pcpp::NetworkUtils::getInstance().getMacAddress(ipAddr, liveDev, time);
			if (result != pcpp::MacAddress::Zero)
				break;
		}

		pcpp::Logger::getInstance().enableLogs();
		if (result != pcpp::MacAddress::Zero)
			break;
	}

	if (foundValidIpAddr)
	{
		PTF_ASSERT_NOT_EQUAL(result, pcpp::MacAddress::Zero);
	}
}  // TestGetMacAddress

PTF_TEST_CASE(TestIPv4Network)
{
	// Invalid c'tor: IPv4 address + prefix len
	PTF_ASSERT_RAISES(pcpp::IPv4Network(pcpp::IPv4Address("1.1.1.1"), -1), std::invalid_argument,
	                  "prefixLen must be an integer between 0 and 32");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(pcpp::IPv4Address("1.1.1.1"), 33), std::invalid_argument,
	                  "prefixLen must be an integer between 0 and 32");

	// Invalid c'tor: IPv4 address + netmask
	PTF_ASSERT_RAISES(pcpp::IPv4Network(pcpp::IPv4Address("1.1.1.1"), "invalid"), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: invalid");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(pcpp::IPv4Address("1.1.1.1"), "999.999.999.999"), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: 999.999.999.999");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(pcpp::IPv4Address("1.1.1.1"), "255.255.0.255"), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: 255.255.0.255");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(pcpp::IPv4Address("1.1.1.1"), "10.10.10.10"), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: 10.10.10.10");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(pcpp::IPv4Address("1.1.1.1"), "0.255.255.255"), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: 0.255.255.255");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(pcpp::IPv4Address("1.1.1.1"), "127.255.255.255"), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: 127.255.255.255");

	// Invalid c'tor: address + netmask in one string
	PTF_ASSERT_RAISES(pcpp::IPv4Network(std::string("invalid")), std::invalid_argument,
	                  "The input should be in the format of <address>/<netmask> or <address>/<prefixLength>");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(std::string("invalid/255.255.255.0")), std::invalid_argument,
	                  "The input doesn't contain a valid IPv4 network prefix: invalid");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(std::string("1.1.1.1/255.255.255.0/24")), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: 255.255.255.0/24");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(std::string("1.1.1.1/33")), std::invalid_argument,
	                  "Prefix length must be an integer between 0 and 32");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(std::string("1.1.1.1/-1")), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: -1");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(std::string("1.1.1.1/invalid")), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: invalid");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(std::string("1.1.1.1/999.999.999.999")), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: 999.999.999.999");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(std::string("1.1.1.1/255.255.0.1")), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: 255.255.0.1");
	PTF_ASSERT_RAISES(pcpp::IPv4Network(std::string("1.1.1.1/0.0.255.255")), std::invalid_argument,
	                  "Netmask is not valid IPv4 format: 0.0.255.255");

	// Valid c'tor
	auto addressAsStr = std::string("192.168.10.100");
	auto address = pcpp::IPv4Address(addressAsStr);

	// clang-format off
	auto networksPrefixLensAndNetPrefix = std::vector<std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>> {
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"255.255.255.255", 32, "192.168.10.100", "192.168.10.100", "192.168.10.100", 1},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"255.255.255.0", 24, "192.168.10.0", "192.168.10.1", "192.168.10.254", 256},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"255.255.0.0", 16, "192.168.0.0", "192.168.0.1", "192.168.255.254", 65536},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"255.240.0.0", 12, "192.160.0.0", "192.160.0.1", "192.175.255.254", 1048576},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"255.0.0.0", 8, "192.0.0.0", "192.0.0.1", "192.255.255.254", 16777216},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"192.0.0.0", 2, "192.0.0.0", "192.0.0.1", "255.255.255.254", 1073741824},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"128.0.0.0", 1, "128.0.0.0", "128.0.0.1", "255.255.255.254", 2147483648},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"0.0.0.0", 0, "0.0.0.0", "0.0.0.1", "255.255.255.254", 4294967296}
	};
	// clang-format on

	for (auto networkPrefixLenAndNetPrefix : networksPrefixLensAndNetPrefix)
	{
		// Valid c'tor: IPv4 address + netmask
		pcpp::IPv4Network iPv4NetworkA(address, std::get<0>(networkPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv4NetworkA.getPrefixLen(), std::get<1>(networkPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv4NetworkA.getNetworkPrefix(), std::get<2>(networkPrefixLenAndNetPrefix));

		// Valid c'tor: IPv4 address + prefix len
		pcpp::IPv4Network iPv4NetworkB(address, std::get<1>(networkPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv4NetworkA.getNetmask(), std::get<0>(networkPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv4NetworkA.getNetworkPrefix(), std::get<2>(networkPrefixLenAndNetPrefix));

		// Valid c'tor: address + netmask in one string
		std::string addressAndNetwork = addressAsStr + "/" + std::get<0>(networkPrefixLenAndNetPrefix);
		pcpp::IPv4Network iPv4NetworkC(addressAndNetwork);
		PTF_ASSERT_EQUAL(iPv4NetworkA.getPrefixLen(), std::get<1>(networkPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv4NetworkA.getNetworkPrefix(), std::get<2>(networkPrefixLenAndNetPrefix));

		// Valid c'tor: address + prefix len in one string
		std::string addressAndPrefixLen =
		    addressAsStr + "/" + std::to_string(std::get<1>(networkPrefixLenAndNetPrefix));
		pcpp::IPv4Network iPv4NetworkD(addressAndPrefixLen);
		PTF_ASSERT_EQUAL(iPv4NetworkA.getNetmask(), std::get<0>(networkPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv4NetworkA.getNetworkPrefix(), std::get<2>(networkPrefixLenAndNetPrefix));

		PTF_ASSERT_EQUAL(iPv4NetworkD.getLowestAddress(), pcpp::IPv4Address(std::get<3>(networkPrefixLenAndNetPrefix)));
		PTF_ASSERT_EQUAL(iPv4NetworkD.getHighestAddress(),
		                 pcpp::IPv4Address(std::get<4>(networkPrefixLenAndNetPrefix)));
		PTF_ASSERT_EQUAL(iPv4NetworkD.getTotalAddressCount(), std::get<5>(networkPrefixLenAndNetPrefix));
	}

	auto ipv4Network = pcpp::IPv4Network(pcpp::IPv4Address("172.16.1.1"), 16);

	PTF_ASSERT_TRUE(ipv4Network.includes(pcpp::IPv4Address("172.16.192.15")));
	PTF_ASSERT_FALSE(ipv4Network.includes(pcpp::IPv4Address("172.17.0.1")));

	for (auto prefixLen = 0; prefixLen < 16; prefixLen++)
	{
		PTF_ASSERT_FALSE(ipv4Network.includes(pcpp::IPv4Network(pcpp::IPv4Address("172.16.192.0"), prefixLen)));
	}

	for (auto prefixLen = 16; prefixLen <= 32; prefixLen++)
	{
		PTF_ASSERT_TRUE(ipv4Network.includes(pcpp::IPv4Network(pcpp::IPv4Address("172.16.192.0"), prefixLen)));
	}

	PTF_ASSERT_FALSE(ipv4Network.includes(pcpp::IPv4Network(pcpp::IPv4Address("172.16.192.0"), 8)));

	auto ipv4Network2 = pcpp::IPv4Network(pcpp::IPv4Address("172.0.0.0"), 16);
	PTF_ASSERT_FALSE(ipv4Network2.includes(pcpp::IPv4Network(pcpp::IPv4Address("172.17.0.1"), 8)));

	// to string
	PTF_ASSERT_EQUAL(ipv4Network.toString(), "172.16.0.0/16");
	std::stringstream stream;
	stream << ipv4Network;
	PTF_ASSERT_EQUAL(stream.str(), "172.16.0.0/16");
}  // TestIPv4Network

PTF_TEST_CASE(TestIPv6Network)
{
	// Invalid c'tor: IPv6 address + prefix len
	PTF_ASSERT_RAISES(pcpp::IPv6Network(pcpp::IPv6Address("2001:db8::"), 129), std::invalid_argument,
	                  "prefixLen must be an integer between 0 and 128");

	// Invalid c'tor: IPv6 address + netmask
	PTF_ASSERT_RAISES(pcpp::IPv6Network(pcpp::IPv6Address("2001:db8::"), "invalid"), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: invalid");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(pcpp::IPv6Address("2001:db8::"), "ffff:ff10::"), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: ffff:ff10::");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(pcpp::IPv6Address("2001:db8::"), "ffff:ee00::"), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: ffff:ee00::");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(pcpp::IPv6Address("2001:db8::"), "7f00::"), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: 7f00::");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(pcpp::IPv6Address("2001:db8::"), "ffff::ffff"), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: ffff::ffff");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(pcpp::IPv6Address("2001:db8::"), "f000::0001"), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: f000::0001");

	// Invalid c'tor: address + netmask in one string
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("invalid")), std::invalid_argument,
	                  "The input should be in the format of <address>/<netmask> or <address>/<prefixLength>");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("invalid/32")), std::invalid_argument,
	                  "The input doesn't contain a valid IPv6 network prefix: invalid");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("ef3c:7157:a084:23c0::/32/24")), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: 32/24");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("ef3c:7157:a084:23c0::/255.255.0.0")), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: 255.255.0.0");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("ef3c:7157:a084:23c0::/130")), std::invalid_argument,
	                  "Prefix length must be an integer between 0 and 128");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("ef3c:7157:a084:23c0::/-1")), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: -1");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("ef3c:7157:a084:23c0::/invalid")), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: invalid");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("ef3c:7157:a084:23c0::/a2cb:d625::")), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: a2cb:d625::");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("ef3c:7157:a084:23c0::/ffff::0001")), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: ffff::0001");
	PTF_ASSERT_RAISES(pcpp::IPv6Network(std::string("ef3c:7157:a084:23c0::/0fff::")), std::invalid_argument,
	                  "Netmask is not valid IPv6 format: 0fff::");

	// Valid c'tor
	auto addressAsStr = std::string("39e1:f90e:14dd:f9a1:4d0a:7f9f:da18:5746");
	auto address = pcpp::IPv6Address(addressAsStr);

	// clang-format off
	auto netmasksPrefixLensAndNetPrefix = std::vector<std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>> {
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128, "39e1:f90e:14dd:f9a1:4d0a:7f9f:da18:5746", "39e1:f90e:14dd:f9a1:4d0a:7f9f:da18:5746", "39e1:f90e:14dd:f9a1:4d0a:7f9f:da18:5746", 1},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8", 125, "39e1:f90e:14dd:f9a1:4d0a:7f9f:da18:5740", "39e1:f90e:14dd:f9a1:4d0a:7f9f:da18:5741", "39e1:f90e:14dd:f9a1:4d0a:7f9f:da18:5747", 8},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ffff:ffff:ffff:ffff:8000::", 65, "39e1:f90e:14dd:f9a1::", "39e1:f90e:14dd:f9a1::1", "39e1:f90e:14dd:f9a1:7fff:ffff:ffff:ffff", 9223372036854775808ULL},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ffff:ffff:ffff:ffff::", 64, "39e1:f90e:14dd:f9a1::", "39e1:f90e:14dd:f9a1::1", "39e1:f90e:14dd:f9a1:ffff:ffff:ffff:ffff", 0},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ffff:ffff::", 32, "39e1:f90e::", "39e1:f90e::1", "39e1:f90e:ffff:ffff:ffff:ffff:ffff:ffff", 0},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ffff:e000::", 19, "39e1:e000::", "39e1:e000::1", "39e1:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ffff:8000::", 17, "39e1:8000::", "39e1:8000::1", "39e1:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ffff::", 16, "39e1::", "39e1::1", "39e1:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ff80::", 9, "3980::", "3980::1", "39ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"ff00::", 8, "3900::", "3900::1", "39ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"fc00::", 6, "3800::", "3800::1", "3bff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"c000::", 2, "00::", "00::1", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0},
		std::tuple<std::string, uint8_t, std::string, std::string, std::string, uint64_t>{"::", 0, "::", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0}
	};
	// clang-format on

	for (auto netmaskPrefixLenAndNetPrefix : netmasksPrefixLensAndNetPrefix)
	{
		// Valid c'tor: IPv6 address + netmask
		pcpp::IPv6Network iPv6NetworkA(address, std::get<0>(netmaskPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv6NetworkA.getPrefixLen(), std::get<1>(netmaskPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv6NetworkA.getNetworkPrefix(), std::get<2>(netmaskPrefixLenAndNetPrefix));

		// Valid c'tor: IPv6 address + prefix len
		pcpp::IPv6Network iPv6NetworkB(address, std::get<1>(netmaskPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv6NetworkB.getNetmask(), std::get<0>(netmaskPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv6NetworkB.getNetworkPrefix(), std::get<2>(netmaskPrefixLenAndNetPrefix));

		// Valid c'tor: address + netmask in one string
		std::string addressAndNetmask = addressAsStr + "/" + std::get<0>(netmaskPrefixLenAndNetPrefix);
		pcpp::IPv6Network iPv6NetworkC(addressAndNetmask);
		PTF_ASSERT_EQUAL(iPv6NetworkC.getPrefixLen(), std::get<1>(netmaskPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv6NetworkC.getNetworkPrefix(), std::get<2>(netmaskPrefixLenAndNetPrefix));

		// Valid c'tor: address + prefix len in one string
		std::string addressAndPrefixLen =
		    addressAsStr + "/" + std::to_string(std::get<1>(netmaskPrefixLenAndNetPrefix));
		pcpp::IPv6Network iPv6NetworkD(addressAndPrefixLen);
		PTF_ASSERT_EQUAL(iPv6NetworkD.getNetmask(), std::get<0>(netmaskPrefixLenAndNetPrefix));
		PTF_ASSERT_EQUAL(iPv6NetworkD.getNetworkPrefix(), std::get<2>(netmaskPrefixLenAndNetPrefix));

		PTF_ASSERT_EQUAL(iPv6NetworkD.getLowestAddress(), pcpp::IPv6Address(std::get<3>(netmaskPrefixLenAndNetPrefix)));
		PTF_ASSERT_EQUAL(iPv6NetworkD.getHighestAddress(),
		                 pcpp::IPv6Address(std::get<4>(netmaskPrefixLenAndNetPrefix)));
		auto expectedNumOfAddresses = std::get<5>(netmaskPrefixLenAndNetPrefix);
		if (expectedNumOfAddresses != 0)
		{
			PTF_ASSERT_EQUAL(iPv6NetworkD.getTotalAddressCount(), expectedNumOfAddresses);
		}
		else
		{
			PTF_ASSERT_RAISES(iPv6NetworkD.getTotalAddressCount(), std::out_of_range,
			                  "Number of addresses exceeds uint64_t");
		}
	}

	auto ipv6Network = pcpp::IPv6Network(pcpp::IPv6Address("a88e:2765:5349:01f9:9a9a:a444:2739:2f4a"), 64);

	PTF_ASSERT_TRUE(ipv6Network.includes(pcpp::IPv6Address("a88e:2765:5349:01f9::")));
	PTF_ASSERT_TRUE(ipv6Network.includes(pcpp::IPv6Address("a88e:2765:5349:01f9:9a9a:a444:2739:2f4a")));
	PTF_ASSERT_TRUE(ipv6Network.includes(pcpp::IPv6Address("a88e:2765:5349:01f9:ffff:ffff:ffff:ffff")));
	PTF_ASSERT_FALSE(ipv6Network.includes(pcpp::IPv6Address("a88e:2765:5349:01fa::")));
	PTF_ASSERT_FALSE(ipv6Network.includes(pcpp::IPv6Address("a88e:2765:5349:01f8::")));
	PTF_ASSERT_FALSE(ipv6Network.includes(pcpp::IPv6Address("a88e::")));

	for (auto prefixLen = 0; prefixLen < 64; prefixLen++)
	{
		PTF_ASSERT_FALSE(ipv6Network.includes(
		    pcpp::IPv6Network(pcpp::IPv6Address("a88e:2765:5349:01f9:9a9a:a444:2739:2f4a"), prefixLen)));
	}

	for (auto prefixLen = 64; prefixLen <= 128; prefixLen++)
	{
		PTF_ASSERT_TRUE(ipv6Network.includes(
		    pcpp::IPv6Network(pcpp::IPv6Address("a88e:2765:5349:01f9:9a9a:a444:2739:2f4a"), prefixLen)));
	}

	PTF_ASSERT_FALSE(
	    ipv6Network.includes(pcpp::IPv6Network(pcpp::IPv6Address("4447:3c98:ee01:fd0a:bf73:ad00:89ac:1a89"), 64)));

	// to string
	PTF_ASSERT_EQUAL(ipv6Network.toString(), "a88e:2765:5349:1f9::/64");
	std::stringstream stream;
	stream << ipv6Network;
	PTF_ASSERT_EQUAL(stream.str(), "a88e:2765:5349:1f9::/64");
}  // TestIPv6Network

PTF_TEST_CASE(TestIPNetwork)
{
	// clang-format off
	auto networkInfos = std::vector<std::tuple<std::string, pcpp::IPAddress, std::uint8_t, std::string, pcpp::IPAddress, int, pcpp::IPAddress, pcpp::IPAddress, uint64_t>> {
		std::tuple<std::string, pcpp::IPAddress, std::uint8_t, std::string, pcpp::IPAddress, int, pcpp::IPAddress, pcpp::IPAddress, uint64_t>{"192.168.1.1", pcpp::IPv4Address("192.168.1.1"), 16, "255.255.0.0", pcpp::IPv4Address("192.168.0.0"), 4, pcpp::IPv4Address("192.168.0.1"), pcpp::IPv4Address("192.168.255.254"), 65536},
		std::tuple<std::string, pcpp::IPAddress, std::uint8_t, std::string, pcpp::IPAddress, int, pcpp::IPAddress, pcpp::IPAddress, uint64_t>{"fe26:d0a1:beb6:5957:e77a:9983:ec84:b23e", pcpp::IPv6Address("fe26:d0a1:beb6:5957:e77a:9983:ec84:b23e"), 64, "ffff:ffff:ffff:ffff::", pcpp::IPv6Address("fe26:d0a1:beb6:5957::"), 6, pcpp::IPv6Address("fe26:d0a1:beb6:5957::1"), pcpp::IPv6Address("fe26:d0a1:beb6:5957:ffff:ffff:ffff:ffff"), 0}
	};
	// clang-format on

	for (auto networkInfo : networkInfos)
	{
		// Valid c'tor: IP address + netmask
		pcpp::IPNetwork networkA(std::get<1>(networkInfo), std::get<3>(networkInfo));
		PTF_ASSERT_EQUAL(networkA.getPrefixLen(), std::get<2>(networkInfo));
		PTF_ASSERT_EQUAL(networkA.getNetworkPrefix(), std::get<4>(networkInfo));

		// Valid c'tor: IP address + prefix len
		pcpp::IPNetwork networkB(std::get<1>(networkInfo), std::get<2>(networkInfo));
		PTF_ASSERT_EQUAL(networkB.getNetmask(), std::get<3>(networkInfo));
		PTF_ASSERT_EQUAL(networkB.getNetworkPrefix(), std::get<4>(networkInfo));

		// Valid c'tor: address + netmask in one string
		pcpp::IPNetwork networkC(std::get<0>(networkInfo) + "/" + std::get<3>(networkInfo));
		PTF_ASSERT_EQUAL(networkC.getPrefixLen(), std::get<2>(networkInfo));
		PTF_ASSERT_EQUAL(networkC.getNetworkPrefix(), std::get<4>(networkInfo));

		// Valid c'tor: address + prefix len in one string
		pcpp::IPNetwork networkD(std::get<0>(networkInfo) + "/" + std::to_string(std::get<2>(networkInfo)));
		PTF_ASSERT_EQUAL(networkD.getNetmask(), std::get<3>(networkInfo));
		PTF_ASSERT_EQUAL(networkD.getNetworkPrefix(), std::get<4>(networkInfo));

		if (std::get<5>(networkInfo) == 4)
		{
			PTF_ASSERT_TRUE(networkD.isIPv4Network());
			PTF_ASSERT_FALSE(networkD.isIPv6Network());
		}
		else
		{
			PTF_ASSERT_TRUE(networkD.isIPv6Network());
			PTF_ASSERT_FALSE(networkD.isIPv4Network());
		}

		PTF_ASSERT_EQUAL(networkD.getLowestAddress(), std::get<6>(networkInfo));
		PTF_ASSERT_EQUAL(networkD.getHighestAddress(), std::get<7>(networkInfo));

		if (std::get<8>(networkInfo) != 0)
		{
			PTF_ASSERT_EQUAL(networkD.getTotalAddressCount(), std::get<8>(networkInfo));
		}
		else
		{
			PTF_ASSERT_RAISES(networkD.getTotalAddressCount(), std::out_of_range,
			                  "Number of addresses exceeds uint64_t");
		}
	}

	// test include
	auto ipv4Network = pcpp::IPNetwork(pcpp::IPv4Address("10.1.2.3"), 24);

	PTF_ASSERT_FALSE(ipv4Network.includes(pcpp::IPv6Address("4348:58d6:a1c3:3fec:1726:b1e4:30ae:fe2d")));
	PTF_ASSERT_FALSE(ipv4Network.includes(pcpp::IPv4Address("10.1.3.1")));
	PTF_ASSERT_TRUE(ipv4Network.includes(pcpp::IPv4Address("10.1.2.10")));

	PTF_ASSERT_FALSE(ipv4Network.includes(pcpp::IPNetwork("4348::/16")));
	PTF_ASSERT_FALSE(ipv4Network.includes(pcpp::IPNetwork("10.1.2.3/20")));
	PTF_ASSERT_TRUE(ipv4Network.includes(pcpp::IPNetwork("10.1.2.3/25")));

	auto ipv6Network = pcpp::IPNetwork(pcpp::IPv6Address("4348:58d6::"), 32);

	PTF_ASSERT_FALSE(ipv6Network.includes(pcpp::IPv4Address("10.1.2.10")));
	PTF_ASSERT_FALSE(ipv6Network.includes(pcpp::IPv6Address("4348:58d7::")));
	PTF_ASSERT_TRUE(ipv6Network.includes(pcpp::IPv6Address("4348:58d6:a1c3:3fec:1726:b1e4:30ae:fe2d")));

	PTF_ASSERT_FALSE(ipv6Network.includes(pcpp::IPNetwork("10.1.2.3/20")));
	PTF_ASSERT_FALSE(ipv6Network.includes(pcpp::IPNetwork("4348:58d6::/31")));
	PTF_ASSERT_TRUE(ipv6Network.includes(pcpp::IPNetwork("4348:58d6:a1c3::/48")));

	// to string
	PTF_ASSERT_EQUAL(ipv4Network.toString(), "10.1.2.0/24");
	std::stringstream stream;
	stream << ipv4Network;
	PTF_ASSERT_EQUAL(stream.str(), "10.1.2.0/24");

	PTF_ASSERT_EQUAL(ipv6Network.toString(), "4348:58d6::/32");
	stream.str("");
	stream << ipv6Network;
	PTF_ASSERT_EQUAL(stream.str(), "4348:58d6::/32")

	// copy c'tor
	auto ipv4NetworkCopy = pcpp::IPNetwork(ipv4Network);
	PTF_ASSERT_EQUAL(ipv4NetworkCopy.toString(), "10.1.2.0/24");

	auto ipv6NetworkCopy = pcpp::IPNetwork(ipv6Network);
	PTF_ASSERT_EQUAL(ipv6NetworkCopy.toString(), "4348:58d6::/32");

	// assignment operator
	ipv4NetworkCopy = ipv6Network;
	PTF_ASSERT_EQUAL(ipv4NetworkCopy.toString(), "4348:58d6::/32");
	ipv6NetworkCopy = ipv4Network;
	PTF_ASSERT_EQUAL(ipv6NetworkCopy.toString(), "10.1.2.0/24");

	ipv4Network = ipv6NetworkCopy;
	PTF_ASSERT_EQUAL(ipv4Network.toString(), "10.1.2.0/24");
	ipv6Network = ipv4NetworkCopy;
	PTF_ASSERT_EQUAL(ipv6Network.toString(), "4348:58d6::/32");
}  // TestIPNetwork
