#include "EndianPortable.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "../TestDefinition.h"

PTF_TEST_CASE(TestIPAddress)
{
	pcpp::IPAddress::Ptr_t ip4Addr = pcpp::IPAddress::fromString((char*)"10.0.0.4");
	PTF_ASSERT_NOT_NULL(ip4Addr.get());
	PTF_ASSERT_EQUAL(ip4Addr->getType(), pcpp::IPAddress::IPv4AddressType, enum);
	PTF_ASSERT_EQUAL(ip4Addr->toString(), "10.0.0.4", string);
	pcpp::IPv4Address* ip4AddrAfterCast = static_cast<pcpp::IPv4Address*>(ip4Addr.get());
	PTF_ASSERT_EQUAL(ip4AddrAfterCast->toInt(), htobe32(0x0A000004), u32);
	pcpp::IPv4Address secondIPv4Address(std::string("1.1.1.1"));
	secondIPv4Address = *ip4AddrAfterCast;
	PTF_ASSERT_TRUE(secondIPv4Address.isValid());
	PTF_ASSERT_EQUAL((*ip4AddrAfterCast),secondIPv4Address, object);

	pcpp::IPv4Address ipv4Addr("10.0.0.4"), subnet1("10.0.0.0"), subnet2("10.10.0.0"), mask("255.255.255.0");
	PTF_ASSERT_TRUE(ipv4Addr.isValid());
	PTF_ASSERT_TRUE(subnet1.isValid());
	PTF_ASSERT_TRUE(subnet2.isValid());
	PTF_ASSERT_TRUE(mask.isValid());
	PTF_ASSERT_TRUE(ipv4Addr.matchSubnet(subnet1, mask));
	PTF_ASSERT_FALSE(ipv4Addr.matchSubnet(subnet2, mask));

	pcpp::IPv4Address badAddress(std::string("sdgdfgd"));
	PTF_ASSERT_FALSE(badAddress.isValid());
	pcpp::IPv4Address anotherBadAddress = pcpp::IPv4Address(std::string("321.123.1000.1"));
	PTF_ASSERT_FALSE(anotherBadAddress.isValid());

	std::string ip6AddrString("2607:f0d0:1002:51::4");
	pcpp::IPAddress::Ptr_t ip6Addr = pcpp::IPAddress::fromString(ip6AddrString);
	PTF_ASSERT_NOT_NULL(ip6Addr.get());
	PTF_ASSERT_EQUAL(ip6Addr->getType(), pcpp::IPAddress::IPv6AddressType, enum);
	PTF_ASSERT_EQUAL(ip6Addr->toString(), "2607:f0d0:1002:51::4", string);
	pcpp::IPv6Address* ip6AddrAfterCast = static_cast<pcpp::IPv6Address*>(ip6Addr.get());
	size_t length = 0;
	uint8_t* addrAsByteArray;
	ip6AddrAfterCast->copyTo(&addrAsByteArray, length);
	PTF_ASSERT_EQUAL(length, 16, size);
	uint8_t expectedByteArray[16] = { 0x26, 0x07, 0xF0, 0xD0, 0x10, 0x02, 0x00, 0x51, 0x00, 0x00 , 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 };
	for (int i = 0; i < 16; i++)
	{
		PTF_ASSERT_EQUAL(addrAsByteArray[i], expectedByteArray[i], u8);
	}

	delete [] addrAsByteArray;
	ip6Addr = pcpp::IPAddress::fromString(std::string("2607:f0d0:1002:0051:0000:0000:0000:0004"));
	PTF_ASSERT_NOT_NULL(ip6Addr.get());
	PTF_ASSERT_EQUAL(ip6Addr->getType(), pcpp::IPAddress::IPv6AddressType, enum);
	PTF_ASSERT_EQUAL(ip6Addr->toString(), "2607:f0d0:1002:0051:0000:0000:0000:0004", string);
	pcpp::IPv6Address secondIPv6Address(std::string("2607:f0d0:1002:52::5"));
	ip6AddrAfterCast = static_cast<pcpp::IPv6Address*>(ip6Addr.get());
	secondIPv6Address = *ip6AddrAfterCast;
	PTF_ASSERT_TRUE(ip6Addr->isValid());
	PTF_ASSERT_EQUAL((*ip6AddrAfterCast), secondIPv6Address, object);

	char badIp6AddressStr[] = "lasdfklsdkfdls";
	pcpp::IPv6Address badIp6Address(badIp6AddressStr);
	PTF_ASSERT_FALSE(badIp6Address.isValid());
	pcpp::IPv6Address anotherBadIp6Address = badIp6Address;
	PTF_ASSERT_FALSE(anotherBadIp6Address.isValid());
} // TestIPAddress



PTF_TEST_CASE(TestMacAddress)
{
	pcpp::MacAddress macAddr1(0x11,0x2,0x33,0x4,0x55,0x6);
	PTF_ASSERT_TRUE(macAddr1.isValid());
	pcpp::MacAddress macAddr2(0x11,0x2,0x33,0x4,0x55,0x6);
	PTF_ASSERT_TRUE(macAddr2.isValid());
	PTF_ASSERT_EQUAL(macAddr1, macAddr2, object);

	pcpp::MacAddress macAddr3(std::string("11:02:33:04:55:06"));
	PTF_ASSERT_TRUE(macAddr3.isValid());
	PTF_ASSERT_EQUAL(macAddr1, macAddr3, object);

	uint8_t addrAsArr[6] = { 0x11, 0x2, 0x33, 0x4, 0x55, 0x6 };
	pcpp::MacAddress macAddr4(addrAsArr);
	PTF_ASSERT_TRUE(macAddr4.isValid());
	PTF_ASSERT_EQUAL(macAddr1, macAddr4, object);

	PTF_ASSERT_EQUAL(macAddr1.toString(), std::string("11:02:33:04:55:06"), string);

	uint8_t* arrToCopyTo = NULL;
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
	PTF_ASSERT_EQUAL(mac6, macAddr1, object);
	mac6 = macAddr2;
	PTF_ASSERT_TRUE(mac6.isValid());
	PTF_ASSERT_EQUAL(mac6, macAddr2, object);

	pcpp::MacAddress macWithZero("aa:aa:00:aa:00:aa");
	pcpp::MacAddress macWrong1("aa:aa:aa:aa:aa:aa:bb:bb:bb:bb");
	pcpp::MacAddress macWrong2("aa:aa:aa");
	pcpp::MacAddress macWrong3("aa:aa:aa:ZZ:aa:aa");
	PTF_ASSERT_TRUE(macWithZero.isValid());
	PTF_ASSERT_FALSE(macWrong1.isValid());
	PTF_ASSERT_FALSE(macWrong2.isValid());
	PTF_ASSERT_FALSE(macWrong3.isValid());
} // TestMacAddress