#include "../TestDefinition.h"
#include "../Common/TestUtils.h"
#include "../Common/GlobalTestArgs.h"
#include <sstream>
#include <algorithm>
#include "EndianPortable.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "LRUList.h"
#include "NetworkUtils.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"


extern PcapTestArgs PcapTestGlobalArgs;

PTF_TEST_CASE(TestIPAddress)
{
	pcpp::IPAddress ip4Addr = pcpp::IPAddress("10.0.0.4");
	PTF_ASSERT_TRUE(ip4Addr.isValid());
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
	PTF_ASSERT_TRUE(secondIPv4Address.isValid());
	PTF_ASSERT_EQUAL(ip4AddrFromIpAddr, secondIPv4Address);

	pcpp::IPv4Address ipv4Addr("10.0.0.4"), subnet1("10.0.0.0"), subnet2("10.10.0.0"), mask("255.255.255.0");
	std::string maskedSubnet1("10.0.0.0/24"), maskedSubnet2("10.10.0.0/24");
	std::string invalidMaskedSubnet1("aaaa"), invalidMaskedSubnet2("10.0.0.0"), invalidMaskedSubnet3("10.0.0.0/aa"), invalidMaskedSubnet4("10.0.0.0/33"), invalidMaskedSubnet5("999.999.1.1/24");
	PTF_ASSERT_TRUE(ipv4Addr.isValid());
	PTF_ASSERT_TRUE(subnet1.isValid());
	PTF_ASSERT_TRUE(subnet2.isValid());
	PTF_ASSERT_TRUE(mask.isValid());
	PTF_ASSERT_TRUE(ipv4Addr.matchSubnet(subnet1, mask));
	PTF_ASSERT_FALSE(ipv4Addr.matchSubnet(subnet2, mask));
	PTF_ASSERT_TRUE(ipv4Addr.matchSubnet(maskedSubnet1));
	PTF_ASSERT_FALSE(ipv4Addr.matchSubnet(maskedSubnet2));
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(ipv4Addr.matchSubnet(invalidMaskedSubnet1));
	PTF_ASSERT_FALSE(ipv4Addr.matchSubnet(invalidMaskedSubnet2));
	PTF_ASSERT_FALSE(ipv4Addr.matchSubnet(invalidMaskedSubnet3));
	PTF_ASSERT_FALSE(ipv4Addr.matchSubnet(invalidMaskedSubnet4));
	PTF_ASSERT_FALSE(ipv4Addr.matchSubnet(invalidMaskedSubnet5));
	pcpp::Logger::getInstance().enableLogs();

	pcpp::IPv4Address badAddress(std::string("sdgdfgd"));
	PTF_ASSERT_FALSE(badAddress.isValid());
	pcpp::IPv4Address anotherBadAddress = pcpp::IPv4Address(std::string("321.123.1000.1"));
	PTF_ASSERT_FALSE(anotherBadAddress.isValid());

	std::string ip6AddrString("2607:f0d0:1002:51::4");
	pcpp::IPAddress ip6Addr = pcpp::IPAddress(ip6AddrString);
	PTF_ASSERT_TRUE(ip6Addr.isValid());
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
	uint8_t expectedByteArray[16] = { 0x26, 0x07, 0xF0, 0xD0, 0x10, 0x02, 0x00, 0x51, 0x00, 0x00 , 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 };
	for (int i = 0; i < 16; i++)
	{
		PTF_ASSERT_EQUAL(addrAsByteArray[i], expectedByteArray[i]);
	}

	ip6Addr = pcpp::IPAddress("2607:f0d0:1002:0051:0000:0000:0000:0004");
	PTF_ASSERT_TRUE(ip6Addr.isValid());
	PTF_ASSERT_EQUAL(ip6Addr.getType(), pcpp::IPAddress::IPv6AddressType, enum);
	PTF_ASSERT_EQUAL(ip6Addr.toString(), "2607:f0d0:1002:51::4");
	pcpp::IPv6Address secondIPv6Address(std::string("2607:f0d0:1002:52::5"));
	ip6AddrFromIpAddr = ip6Addr.getIPv6();
	secondIPv6Address = ip6AddrFromIpAddr;
	PTF_ASSERT_EQUAL(ip6AddrFromIpAddr, secondIPv6Address);

	char badIp6AddressStr[] = "lasdfklsdkfdls";
	pcpp::IPv6Address badIp6Address(badIp6AddressStr);
	PTF_ASSERT_FALSE(badIp6Address.isValid());
	pcpp::IPv6Address anotherBadIp6Address = badIp6Address;
	PTF_ASSERT_FALSE(anotherBadIp6Address.isValid());

	pcpp::IPv6Address ip6Addr2("2607:f0d0:1002:0051:ffff:0000:0000:0004");
	pcpp::IPv6Address subnetIp6Addr01("2607:f0d0:1002:0051::");
	pcpp::IPv6Address subnetIp6Addr02("2607:f0d0:1002:0051:0011::");

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(ip6Addr2.matchSubnet(subnetIp6Addr01, 0));
	pcpp::Logger::getInstance().enableLogs();
	for(int i = 1; i <= 64; ++i)
	{
		PTF_ASSERT_TRUE(ip6Addr2.matchSubnet(subnetIp6Addr01, i));
		PTF_ASSERT_TRUE(ip6Addr2.matchSubnet(subnetIp6Addr02, i));
	}

	for(int i = 65; i <= 127; ++i)
	{
		PTF_ASSERT_FALSE(ip6Addr2.matchSubnet(subnetIp6Addr01, i));
		PTF_ASSERT_FALSE(ip6Addr2.matchSubnet(subnetIp6Addr02, i));
	}

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
} // TestIPAddress


PTF_TEST_CASE(TestMacAddress)
{
	pcpp::MacAddress macAddr1(0x11,0x2,0x33,0x4,0x55,0x6);
	PTF_ASSERT_TRUE(macAddr1.isValid());
	pcpp::MacAddress macAddr2(0x11,0x2,0x33,0x4,0x55,0x6);
	PTF_ASSERT_TRUE(macAddr2.isValid());
	PTF_ASSERT_EQUAL(macAddr1, macAddr2);

	pcpp::MacAddress macAddr3(std::string("11:02:33:04:55:06"));
	PTF_ASSERT_TRUE(macAddr3.isValid());
	PTF_ASSERT_EQUAL(macAddr1, macAddr3);

	uint8_t addrAsArr[6] = { 0x11, 0x2, 0x33, 0x4, 0x55, 0x6 };
	pcpp::MacAddress macAddr4(addrAsArr);
	PTF_ASSERT_TRUE(macAddr4.isValid());
	PTF_ASSERT_EQUAL(macAddr1, macAddr4);

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
	delete [] arrToCopyTo;

	uint8_t macBytes[6];
	macAddr3.copyTo(macBytes);
	PTF_ASSERT_BUF_COMPARE(macBytes, addrAsArr, 6);

	#if __cplusplus > 199711L || _MSC_VER >= 1800
	pcpp::MacAddress macCpp11Valid { 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB };
	pcpp::MacAddress macCpp11Wrong { 0xBB, 0xBB, 0xBB, 0xBB, 0xBB };
	PTF_ASSERT_TRUE(macCpp11Valid.isValid());
	PTF_ASSERT_FALSE(macCpp11Wrong.isValid());
	#endif

	pcpp::MacAddress mac6(macAddr1);
	PTF_ASSERT_TRUE(mac6.isValid());
	PTF_ASSERT_EQUAL(mac6, macAddr1);
	mac6 = macAddr2;
	PTF_ASSERT_TRUE(mac6.isValid());
	PTF_ASSERT_EQUAL(mac6, macAddr2);

	pcpp::MacAddress macWithZero("aa:aa:00:aa:00:aa");
	pcpp::MacAddress macWrong1("aa:aa:aa:aa:aa:aa:bb:bb:bb:bb");
	pcpp::MacAddress macWrong2("aa:aa:aa");
	pcpp::MacAddress macWrong3("aa:aa:aa:ZZ:aa:aa");
	PTF_ASSERT_TRUE(macWithZero.isValid());
	PTF_ASSERT_FALSE(macWrong1.isValid());
	PTF_ASSERT_FALSE(macWrong2.isValid());
	PTF_ASSERT_FALSE(macWrong3.isValid());
} // TestMacAddress


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
} // TestLRUList


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
} // TestGeneralUtils


PTF_TEST_CASE(TestGetMacAddress)
{
	pcpp::PcapLiveDevice* liveDev = nullptr;
	pcpp::IPv4Address ipToSearch(PcapTestGlobalArgs.ipToSendReceivePackets.c_str());
	liveDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipToSearch);
	PTF_ASSERT_NOT_NULL(liveDev);
	PTF_ASSERT_TRUE(liveDev->open());
	DeviceTeardown devTeardown(liveDev);

	//fetch all IP addresses from arp table
	std::string ipsInArpTableAsString;
#ifdef _WIN32
	ipsInArpTableAsString = pcpp::executeShellCommand("arp -a | for /f \"tokens=1\" \%i in ('findstr dynamic') do @echo \%i");
	ipsInArpTableAsString.erase(std::remove(ipsInArpTableAsString.begin(), ipsInArpTableAsString.end(), ' '), ipsInArpTableAsString.end() ) ;
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
		pcpp::IPv4Address ipAddr(ip);
		if (!ipAddr.isValid())
			continue;

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
} // TestGetMacAddress
