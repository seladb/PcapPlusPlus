#define LOG_MODULE PacketLogModuleVrrpLayer

#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "VrrpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"


PTF_TEST_CASE(VrrpParsingTest)
{
	timeval time = {};
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/VRRP-V2.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/VRRP-V3-IPv4.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/VRRP-V3-IPv6.dat");

	pcpp::Packet vrrpv2Packet(&rawPacket1);
	pcpp::Packet vrrpv3IPv4Packet(&rawPacket2);
	pcpp::Packet vrrpv3IPv6Packet(&rawPacket3);

	PTF_ASSERT_TRUE(vrrpv2Packet.isPacketOfType(pcpp::VRRP))
	PTF_ASSERT_TRUE(vrrpv2Packet.isPacketOfType(pcpp::VRRPv2))
	PTF_ASSERT_FALSE(vrrpv2Packet.isPacketOfType(pcpp::VRRPv3))
	auto vrrpV2Layer = vrrpv2Packet.getLayerOfType<pcpp::VrrpV2Layer>();
	PTF_ASSERT_EQUAL(vrrpV2Layer->getType(), pcpp::VrrpLayer::VrrpType::VrrpType_Advertisement, enum)
	PTF_ASSERT_EQUAL(vrrpV2Layer->getVersion(), 2)
	PTF_ASSERT_EQUAL(vrrpV2Layer->getVirtualRouterID(), 1)
	PTF_ASSERT_EQUAL(vrrpV2Layer->getPriority(), 100);
	PTF_ASSERT_EQUAL(vrrpV2Layer->getPriorityAsEnum(), pcpp::VrrpLayer::VrrpPriority::Default, enum)
	PTF_ASSERT_EQUAL(vrrpV2Layer->getAddressType(), pcpp::IPAddress::IPv4AddressType, enum)
	PTF_ASSERT_EQUAL(vrrpV2Layer->getIPAddressesCount(), 3)
	PTF_ASSERT_EQUAL(vrrpV2Layer->getAuthType(), 0)
	PTF_ASSERT_EQUAL(vrrpV2Layer->getAuthTypeAsEnum(), pcpp::VrrpV2Layer::VrrpAuthType::NoAuthentication, enumclass)
	PTF_ASSERT_EQUAL(vrrpV2Layer->getAdvInt(), 1)
	PTF_ASSERT_EQUAL(vrrpV2Layer->getChecksum(), 0x38fa)
	PTF_ASSERT_TRUE(vrrpV2Layer->isChecksumCorrect())

	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.isPacketOfType(pcpp::VRRP))
	PTF_ASSERT_FALSE(vrrpv3IPv4Packet.isPacketOfType(pcpp::VRRPv2))
	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.isPacketOfType(pcpp::VRRPv3))
	auto vrrpV3IPv4Layer = vrrpv3IPv4Packet.getLayerOfType<pcpp::VrrpV3Layer>();
	PTF_ASSERT_EQUAL(vrrpV3IPv4Layer->getType(), pcpp::VrrpLayer::VrrpType::VrrpType_Advertisement, enum)
	PTF_ASSERT_EQUAL(vrrpV3IPv4Layer->getVersion(), 3)
	PTF_ASSERT_EQUAL(vrrpV3IPv4Layer->getVirtualRouterID(), 1)
	PTF_ASSERT_EQUAL(vrrpV3IPv4Layer->getPriority(), 100);
	PTF_ASSERT_EQUAL(vrrpV3IPv4Layer->getPriorityAsEnum(), pcpp::VrrpLayer::VrrpPriority::Default, enum)
	PTF_ASSERT_EQUAL(vrrpV3IPv4Layer->getAddressType(), pcpp::IPAddress::IPv4AddressType, enum)
	PTF_ASSERT_EQUAL(vrrpV3IPv4Layer->getIPAddressesCount(), 2)
	PTF_ASSERT_EQUAL(vrrpV3IPv4Layer->getMaxAdvInt(), 1)
	PTF_ASSERT_EQUAL(vrrpV3IPv4Layer->getChecksum(), 0x484d)
	PTF_ASSERT_TRUE(vrrpV3IPv4Layer->isChecksumCorrect())

	PTF_ASSERT_TRUE(vrrpv3IPv6Packet.isPacketOfType(pcpp::VRRP))
	PTF_ASSERT_FALSE(vrrpv3IPv6Packet.isPacketOfType(pcpp::VRRPv2))
	PTF_ASSERT_TRUE(vrrpv3IPv6Packet.isPacketOfType(pcpp::VRRPv3))
	auto vrrpV3IPv6Layer = vrrpv3IPv6Packet.getLayerOfType<pcpp::VrrpV3Layer>();
	PTF_ASSERT_EQUAL(vrrpV3IPv6Layer->getType(), pcpp::VrrpLayer::VrrpType::VrrpType_Advertisement, enum)
	PTF_ASSERT_EQUAL(vrrpV3IPv6Layer->getVersion(), 3)
	PTF_ASSERT_EQUAL(vrrpV3IPv6Layer->getVirtualRouterID(), 1)
	PTF_ASSERT_EQUAL(vrrpV3IPv6Layer->getPriority(), 100);
	PTF_ASSERT_EQUAL(vrrpV3IPv6Layer->getPriorityAsEnum(), pcpp::VrrpLayer::VrrpPriority::Default, enum)
	PTF_ASSERT_EQUAL(vrrpV3IPv6Layer->getAddressType(), pcpp::IPAddress::IPv6AddressType, enum)
	PTF_ASSERT_EQUAL(vrrpV3IPv6Layer->getIPAddressesCount(), 3)
	PTF_ASSERT_EQUAL(vrrpV3IPv6Layer->getMaxAdvInt(), 1)
	PTF_ASSERT_EQUAL(vrrpV3IPv6Layer->getChecksum(), 0x1071)
	PTF_ASSERT_TRUE(vrrpV3IPv6Layer->isChecksumCorrect())
} // VrrpParsingTest



PTF_TEST_CASE(VrrpCreateAndEditTest)
{
	timeval time = {};
	gettimeofday(&time, nullptr);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/VRRP-V2.dat")
	READ_FILE_INTO_BUFFER(2, "PacketExamples/VRRP-V3-IPv4.dat")
	READ_FILE_INTO_BUFFER(3, "PacketExamples/VRRP-V3-IPv6.dat")

	// VRRP virtual IP addresses
	pcpp::IPAddress ipv4Address1("192.168.0.1");
	pcpp::IPAddress ipv4Address2("192.168.0.2");
	pcpp::IPAddress ipv4Address3("192.168.0.3");
	pcpp::IPAddress ipv6Address1("fe80::254");
	pcpp::IPAddress ipv6Address2("2001:db8::1");
	pcpp::IPAddress ipv6Address3("2001:db8::2");

	// VRRPv2 v2Packet
	pcpp::EthLayer ethLayer1(pcpp::MacAddress("00:00:5e:00:01:01"), pcpp::MacAddress("01:00:5e:00:00:12"));
	pcpp::IPv4Layer ipLayer1(pcpp::IPv4Address("192.168.0.30"), pcpp::IPv4Address("224.0.0.18"));
	ipLayer1.getIPv4Header()->timeToLive = 255;

	pcpp::Packet vrrpv2Packet(1);
	pcpp::VrrpV2Layer vrrpv2Layer(1, 100, 1);

	vrrpv2Layer.addIPAddress(ipv4Address1);
	vrrpv2Layer.addIPAddress(ipv4Address2);
	vrrpv2Layer.addIPAddress(ipv4Address3);

	PTF_ASSERT_EQUAL(vrrpv2Layer.getIPAddresses().size(), 3)

	PTF_ASSERT_TRUE(vrrpv2Packet.addLayer(&ethLayer1))
	PTF_ASSERT_TRUE(vrrpv2Packet.addLayer(&ipLayer1))
	PTF_ASSERT_TRUE(vrrpv2Packet.addLayer(&vrrpv2Layer))

	vrrpv2Packet.computeCalculateFields();
	PTF_ASSERT_TRUE(vrrpv2Layer.removeAllIPAddresses())
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(vrrpv2Layer.removeIPAddressAtIndex(1))
	pcpp::Logger::getInstance().enableLogs();
	vrrpv2Layer.addIPAddress(ipv4Address1);
	vrrpv2Layer.addIPAddress(ipv4Address2);
	vrrpv2Layer.addIPAddress(ipv4Address3);

	vrrpv2Layer.removeAllIPAddresses();

	vrrpv2Layer.addIPAddress(ipv4Address1);
	vrrpv2Layer.addIPAddress(ipv4Address2);
	vrrpv2Layer.addIPAddress(ipv4Address3);

	vrrpv2Layer.removeIPAddressAtIndex(2);
	vrrpv2Layer.addIPAddress(ipv4Address3);

	vrrpv2Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(vrrpv2Packet.getRawPacket()->getRawDataLen(), bufferLength1)
	PTF_ASSERT_BUF_COMPARE(vrrpv2Packet.getRawPacket()->getRawData(), buffer1, bufferLength1)

	//VRRPv3 IPv4 Packet
	pcpp::EthLayer ethLayer2(pcpp::MacAddress("00:00:5e:00:01:01"), pcpp::MacAddress("01:00:5e:00:00:12"));
	pcpp::IPv4Layer ipv4Layer(pcpp::IPv4Address("192.168.0.30"), pcpp::IPv4Address("224.0.0.18"));
	ipv4Layer.getIPv4Header()->timeToLive = 255;

	pcpp::Packet vrrpv3IPv4Packet(1);
	pcpp::VrrpV3Layer vrrpv3IPv4Layer(pcpp::IPAddress::IPv4AddressType, 1 ,100, 1);

	vrrpv3IPv4Layer.addIPAddress(ipv4Address1);
	vrrpv3IPv4Layer.addIPAddress(ipv4Address2);
	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.addLayer(&ethLayer2))
	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.addLayer(&ipv4Layer))
	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.addLayer(&vrrpv3IPv4Layer))
	vrrpv3IPv4Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(vrrpv3IPv4Packet.getRawPacket()->getRawDataLen(), bufferLength2)
	PTF_ASSERT_BUF_COMPARE(vrrpv3IPv4Packet.getRawPacket()->getRawData(), buffer2, bufferLength2)

	//VRRPv3 IPv6 Packet
	pcpp::EthLayer ethLayer3(pcpp::MacAddress("00:00:5e:00:01:01"), pcpp::MacAddress("01:00:5e:00:00:12"));
	pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address("fe80::1"), pcpp::IPv6Address("ff02::12"));
	ipv6Layer.getIPv6Header()->hopLimit = 255;

	pcpp::Packet ipv6Packet(1);
	pcpp::VrrpV3Layer vrrpv3IPv6Layer(pcpp::IPAddress::IPv6AddressType, 1, 100, 1);

	std::vector<pcpp::IPAddress> ipAddresses;
	ipAddresses.push_back(ipv6Address1);
	ipAddresses.push_back(ipv6Address2);
	ipAddresses.push_back(ipv6Address3);
	vrrpv3IPv6Layer.addIPAddresses(ipAddresses);
	PTF_ASSERT_TRUE(ipv6Packet.addLayer(&ethLayer3))
	PTF_ASSERT_TRUE(ipv6Packet.addLayer(&ipv6Layer))
	PTF_ASSERT_TRUE(ipv6Packet.addLayer(&vrrpv3IPv6Layer))
	ipv6Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(ipv6Packet.getRawPacket()->getRawDataLen(), bufferLength3)
	PTF_ASSERT_BUF_COMPARE(ipv6Packet.getRawPacket()->getRawData(), buffer3, bufferLength3)

	FREE_FILE_INTO_BUFFER(1)
	FREE_FILE_INTO_BUFFER(2)
	FREE_FILE_INTO_BUFFER(3)

} // VrrpCreateAndEditTest
