#define LOG_MODULE PacketLogModuleVrrpLayer

#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "Logger.h"
#include "EthLayer.h"
#include "VrrpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"

using namespace pcpp;

PTF_TEST_CASE(VrrpParsingTest) {
	timeval time = {};
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/VRRP-V2.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/VRRP-V3-IPv4.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/VRRP-V3-IPv6.dat");

	Packet vrrpv2Packet(&rawPacket1);
	Packet vrrpv3IPv4Packet(&rawPacket2);
	Packet vrrpv3IPv6Packet(&rawPacket3);

	auto *vrrpV2Layer = vrrpv2Packet.getLayerOfType<VrrpV2Layer>();
	PTF_ASSERT_TRUE(vrrpv2Packet.isPacketOfType(VRRP))
	PTF_ASSERT_TRUE(vrrpv2Packet.isPacketOfType(VRRPv2))
	PTF_ASSERT_FALSE(vrrpv2Packet.isPacketOfType(VRRPv3))
	pcpp::Logger::getInstance().suppressLogs();
	Logger::getInstance().setLogLevel(pcpp::PacketLogModuleVrrpLayer, Logger::Debug);
	PCPP_LOG_DEBUG(vrrpV2Layer->toString());
	pcpp::Logger::getInstance().enableLogs();

	auto *vrrpV3IPv4Layer = vrrpv3IPv4Packet.getLayerOfType<VrrpV3Layer>();
	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.isPacketOfType(VRRP))
	PTF_ASSERT_FALSE(vrrpv3IPv4Packet.isPacketOfType(VRRPv2))
	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.isPacketOfType(VRRPv3))
	pcpp::Logger::getInstance().suppressLogs();
	Logger::getInstance().setLogLevel(pcpp::PacketLogModuleVrrpLayer, Logger::Debug);
	PCPP_LOG_DEBUG(vrrpV3IPv4Layer->toString());
	pcpp::Logger::getInstance().enableLogs();

	auto *vrrpV3IPv6Layer = vrrpv3IPv6Packet.getLayerOfType<VrrpV3Layer>();
	PTF_ASSERT_TRUE(vrrpv3IPv6Packet.isPacketOfType(VRRP))
	PTF_ASSERT_FALSE(vrrpv3IPv6Packet.isPacketOfType(VRRPv2))
	PTF_ASSERT_TRUE(vrrpv3IPv6Packet.isPacketOfType(VRRPv3))
	pcpp::Logger::getInstance().suppressLogs();
	Logger::getInstance().setLogLevel(pcpp::PacketLogModuleVrrpLayer, Logger::Debug);
	PCPP_LOG_DEBUG(vrrpV3IPv6Layer->toString());
	pcpp::Logger::getInstance().enableLogs();
} // VrrpParsingTest



PTF_TEST_CASE(VrrpCreateAndEditTest) {
	timeval time = {};
	gettimeofday(&time, nullptr);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/VRRP-V2.dat")
	READ_FILE_INTO_BUFFER(2, "PacketExamples/VRRP-V3-IPv4.dat")
	READ_FILE_INTO_BUFFER(3, "PacketExamples/VRRP-V3-IPv6.dat")

	// VRRP virtual IP addresses
	IPAddress ipv4Address1("192.168.0.1");
	IPAddress ipv4Address2("192.168.0.2");
	IPAddress ipv4Address3("192.168.0.3");
	IPAddress ipv6Address1("fe80::254");
	IPAddress ipv6Address2("2001:db8::1");
	IPAddress ipv6Address3("2001:db8::2");

	// VRRPv2 v2Packet
	EthLayer ethLayer1(MacAddress("00:00:5e:00:01:01"), MacAddress("01:00:5e:00:00:12"));
	IPv4Layer ipLayer1(IPv4Address("192.168.0.30"), IPv4Address("224.0.0.18"));
	ipLayer1.getIPv4Header()->timeToLive = 255;

	Packet vrrpv2Packet(1);
	VrrpV2Layer vrrpv2Layer;
	vrrp_packet v2Packet = {0};
	v2Packet.version = Vrrp_Version_2;
	v2Packet.type = VrrpType_Advertisement;
	v2Packet.vrId = 1;
	v2Packet.priority = 100;
	vrrpv2_auth_adv authAdv = {0};
	authAdv.authType = VRRP_AUTH_NONE;
	authAdv.advInt = 1;
	VRRP_PACKET_SET_AUTH_ADV_INT(v2Packet.authTypeAdvInt, authAdv);
	vrrpv2Layer.setPacket(&v2Packet);

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
	pcpp::Logger::getInstance().suppressLogs();
	PCPP_LOG_DEBUG(vrrpv2Packet.toString());
	pcpp::Logger::getInstance().enableLogs();

	//VRRPv3 IPv4 Packet
	EthLayer ethLayer2(MacAddress("00:00:5e:00:01:01"), MacAddress("01:00:5e:00:00:12"));
	IPv4Layer ipv4Layer(IPv4Address("192.168.0.30"), IPv4Address("224.0.0.18"));
	ipv4Layer.getIPv4Header()->timeToLive = 255;

	Packet vrrpv3IPv4Packet(1);
	VrrpV3Layer vrrpv3IPv4Layer(IPAddress::IPv4AddressType);
	vrrp_packet v3IPv4Packet = {0};
	v3IPv4Packet.version = Vrrp_Version_3;
	v3IPv4Packet.type = VrrpType_Advertisement;
	v3IPv4Packet.vrId = 1;
	v3IPv4Packet.priority = 100;
	v3IPv4Packet.authTypeAdvInt = htobe16(1);
	vrrpv3IPv4Layer.setPacket(&v3IPv4Packet);

	vrrpv3IPv4Layer.addIPAddress(ipv4Address1);
	vrrpv3IPv4Layer.addIPAddress(ipv4Address2);
	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.addLayer(&ethLayer2))
	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.addLayer(&ipv4Layer))
	PTF_ASSERT_TRUE(vrrpv3IPv4Packet.addLayer(&vrrpv3IPv4Layer))
	vrrpv3IPv4Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(vrrpv3IPv4Packet.getRawPacket()->getRawDataLen(), bufferLength2)
	PTF_ASSERT_BUF_COMPARE(vrrpv3IPv4Packet.getRawPacket()->getRawData(), buffer2, bufferLength2)
	pcpp::Logger::getInstance().suppressLogs();
	PCPP_LOG_DEBUG(vrrpv3IPv4Packet.toString());
	pcpp::Logger::getInstance().enableLogs();

	//VRRPv3 IPv6 Packet
	EthLayer ethLayer3(MacAddress("00:00:5e:00:01:01"), MacAddress("01:00:5e:00:00:12"));
	IPv6Layer ipv6Layer(IPv6Address("fe80::1"), IPv6Address("ff02::12"));
	ipv6Layer.getIPv6Header()->hopLimit = 255;

	Packet ipv6Packet(1);
	VrrpV3Layer vrrpv3IPv6Layer(IPAddress::IPv6AddressType);
	vrrp_packet v3IPv6Packet = {0};
	v3IPv6Packet.version = Vrrp_Version_3;
	v3IPv6Packet.type = VrrpType_Advertisement;
	v3IPv6Packet.vrId = 1;
	v3IPv6Packet.priority = 100;
	v3IPv6Packet.authTypeAdvInt = htobe16(1);
	vrrpv3IPv6Layer.setPacket(&v3IPv6Packet);

	std::vector<IPAddress> ipAddresses;
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
	pcpp::Logger::getInstance().suppressLogs();
	PCPP_LOG_DEBUG(vrrpv3IPv6Layer.toString());
	pcpp::Logger::getInstance().enableLogs();

	FREE_FILE_INTO_BUFFER(1)
	FREE_FILE_INTO_BUFFER(2)
	FREE_FILE_INTO_BUFFER(3)

} // VrrpCreateAndEditTest