#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "Packet.h"
#include "SomeIpLayer.h"
#include "SystemUtils.h"
#include "UdpLayer.h"
#include "VlanLayer.h"
#include <array>
#include <cstring>

class SomeIpTeardown
{
public:
	SomeIpTeardown()
	{}
	~SomeIpTeardown()
	{
		pcpp::SomeIpLayer::removeAllSomeIpPorts();
	}
};

PTF_TEST_CASE(SomeIpPortTest)
{
	// cppcheck-suppress unusedVariable
	SomeIpTeardown someIpTeardown;

	pcpp::SomeIpLayer::addSomeIpPort(1234);
	PTF_ASSERT_TRUE(pcpp::SomeIpLayer::isSomeIpPort(1234));

	pcpp::SomeIpLayer::removeSomeIpPort(1234);
	PTF_ASSERT_FALSE(pcpp::SomeIpLayer::isSomeIpPort(1234));

	pcpp::SomeIpLayer::addSomeIpPort(1235);
	pcpp::SomeIpLayer::addSomeIpPort(1236);
	PTF_ASSERT_TRUE(pcpp::SomeIpLayer::isSomeIpPort(1235));
	PTF_ASSERT_TRUE(pcpp::SomeIpLayer::isSomeIpPort(1236));

	pcpp::SomeIpLayer::removeAllSomeIpPorts();
	PTF_ASSERT_FALSE(pcpp::SomeIpLayer::isSomeIpPort(1235));
	PTF_ASSERT_FALSE(pcpp::SomeIpLayer::isSomeIpPort(1236));
}

PTF_TEST_CASE(SomeIpParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// cppcheck-suppress unusedVariable
	SomeIpTeardown someIpTeardown;
	pcpp::SomeIpLayer::addSomeIpPort(29180);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/someip.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/someip2.dat");
	pcpp::Packet someIpPacket(&rawPacket1);
	pcpp::Packet someIpPacket2(&rawPacket2);

	// Test with one SOME/IP layer
	PTF_ASSERT_TRUE(someIpPacket.isPacketOfType(pcpp::SomeIP));
	pcpp::SomeIpLayer* someIpLayer = someIpPacket.getLayerOfType<pcpp::SomeIpLayer>();
	PTF_ASSERT_NOT_NULL(someIpLayer);
	PTF_ASSERT_EQUAL(someIpLayer->getHeaderLen(), 38);
	PTF_ASSERT_EQUAL(someIpLayer->getMessageID(), 0x6059410c);
	PTF_ASSERT_EQUAL(someIpLayer->getServiceID(), 0x6059);
	PTF_ASSERT_EQUAL(someIpLayer->getMethodID(), 0x410c);
	PTF_ASSERT_EQUAL(someIpLayer->getLengthField(), 30);
	PTF_ASSERT_EQUAL(someIpLayer->getRequestID(), 0x0003000a);
	PTF_ASSERT_EQUAL(someIpLayer->getClientID(), 0x3);
	PTF_ASSERT_EQUAL(someIpLayer->getSessionID(), 0xa);
	PTF_ASSERT_EQUAL(someIpLayer->getProtocolVersion(), 1);
	PTF_ASSERT_EQUAL(someIpLayer->getInterfaceVersion(), 0x5);
	PTF_ASSERT_EQUAL(someIpLayer->getMessageType(), pcpp::SomeIpLayer::MsgType::REQUEST, enumclass);
	PTF_ASSERT_EQUAL(someIpLayer->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::REQUEST);
	PTF_ASSERT_EQUAL(someIpLayer->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpLayer->getPduPayloadSize(), 22);
	PTF_ASSERT_EQUAL(someIpLayer->getPduPayload()[0], 0x40);
	PTF_ASSERT_EQUAL(someIpLayer->getPduPayload()[20], 0x01);
	PTF_ASSERT_EQUAL(someIpLayer->toString(), "SOME/IP Layer, Service ID: 0x6059, Method ID: 0x410c, Length: 30");
	PTF_ASSERT_NULL(someIpLayer->getNextLayer());

	// Test with two SOME/IP layers
	pcpp::SomeIpLayer* someIpLayer2_1 = someIpPacket2.getLayerOfType<pcpp::SomeIpLayer>();
	PTF_ASSERT_NOT_NULL(someIpLayer2_1);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getHeaderLen(), 38);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getMessageID(), 0x6059410c);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getServiceID(), 0x6059);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getMethodID(), 0x410c);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getLengthField(), 30);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getRequestID(), 0x0003000a);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getClientID(), 0x3);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getSessionID(), 0xa);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getProtocolVersion(), 1);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getInterfaceVersion(), 0x5);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getMessageType(), pcpp::SomeIpLayer::MsgType::REQUEST, enumclass);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::REQUEST);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getPduPayloadSize(), 22);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getPduPayload()[0], 0x40);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getPduPayload()[20], 0x01);
	PTF_ASSERT_EQUAL(someIpLayer2_1->toString(), "SOME/IP Layer, Service ID: 0x6059, Method ID: 0x410c, Length: 30");
	PTF_ASSERT_NOT_NULL(someIpLayer2_1->getNextLayer());

	pcpp::SomeIpLayer* someIpLayer2_2 = someIpPacket2.getNextLayerOfType<pcpp::SomeIpLayer>(someIpLayer2_1);
	PTF_ASSERT_NOT_NULL(someIpLayer2_2);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getHeaderLen(), 36);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getMessageID(), 0x6060410d);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getServiceID(), 0x6060);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getMethodID(), 0x410d);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getLengthField(), 28);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getRequestID(), 0x0004000b);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getClientID(), 0x4);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getSessionID(), 0xb);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getProtocolVersion(), 1);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getInterfaceVersion(), 0x6);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getMessageType(), pcpp::SomeIpLayer::MsgType::REQUEST, enumclass);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::REQUEST);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getPduPayloadSize(), 20);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getPduPayload()[0], 0x01);
	PTF_ASSERT_EQUAL(someIpLayer2_2->getPduPayload()[19], 0x14);
	PTF_ASSERT_EQUAL(someIpLayer2_2->toString(), "SOME/IP Layer, Service ID: 0x6060, Method ID: 0x410d, Length: 28");
	PTF_ASSERT_NULL(someIpLayer2_2->getNextLayer());
}

PTF_TEST_CASE(SomeIpCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/someip.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/someip2.dat");

	std::array<uint8_t, 22> data1{ 0x40, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		                           0x00, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00 };

	std::array<uint8_t, 20> data2{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
		                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14 };

	// Test with one SOME/IP layer
	pcpp::SomeIpLayer someipLayer1(0x6059, 0x410c, 0x3, 0xa, 0x5, pcpp::SomeIpLayer::MsgType::REQUEST, 0, data1.data(),
	                               data1.size());
	pcpp::Packet someIpPacket(100);
	PTF_ASSERT_TRUE(someIpPacket.addLayer(&someipLayer1));
	someIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(someIpPacket.getRawPacket()->getRawDataLen(), bufferLength1 - 78);
	PTF_ASSERT_BUF_COMPARE(someIpPacket.getRawPacket()->getRawData(), buffer1 + 78, bufferLength1 - 78);

	// Test with two SOME/IP layers
	pcpp::EthLayer ethLayer2(pcpp::MacAddress("02:7d:fa:01:17:40"), pcpp::MacAddress("02:7d:fa:00:10:01"),
	                         PCPP_ETHERTYPE_VLAN);
	pcpp::VlanLayer vlanLayer2(2, false, 0, PCPP_ETHERTYPE_IP);
	pcpp::IPv6Layer ip6Layer2(pcpp::IPv6Address("fd53:7cb8:0383:0002::0001:0117"),
	                          pcpp::IPv6Address("fd53:7cb8:0383:000e::0014"));
	pcpp::UdpLayer udpLayer2(29300, 29180);
	pcpp::SomeIpLayer someipLayer2_1(0x6059, 0x410c, 0x3, 0xa, 0x5, pcpp::SomeIpLayer::MsgType::REQUEST, 0,
	                                 data1.data(), data1.size());
	pcpp::SomeIpLayer someipLayer2_2(0x6060, 0x410d, 0x4, 0xb, 0x6, pcpp::SomeIpLayer::MsgType::REQUEST, 0,
	                                 data2.data(), data2.size());

	pcpp::Packet someIpPacket2(100);
	PTF_ASSERT_TRUE(someIpPacket2.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(someIpPacket2.addLayer(&vlanLayer2));
	PTF_ASSERT_TRUE(someIpPacket2.addLayer(&ip6Layer2));
	PTF_ASSERT_TRUE(someIpPacket2.addLayer(&udpLayer2));
	PTF_ASSERT_TRUE(someIpPacket2.addLayer(&someipLayer2_1));
	PTF_ASSERT_TRUE(someIpPacket2.addLayer(&someipLayer2_2));
	someIpPacket2.computeCalculateFields();

	PTF_ASSERT_EQUAL(someIpPacket2.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(someIpPacket2.getRawPacket()->getRawData(), buffer2, bufferLength2);

	delete[] buffer1;
	delete[] buffer2;
}

PTF_TEST_CASE(SomeIpTpParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	// cppcheck-suppress unusedVariable
	SomeIpTeardown someIpTeardown;
	pcpp::SomeIpLayer::addSomeIpPort(16832);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SomeIpTp1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/SomeIpTp2.dat");

	pcpp::Packet someIpTpPacket1(&rawPacket1);
	pcpp::Packet someIpTpPacket2(&rawPacket2);

	// Test SOME/IP-TP start packet
	PTF_ASSERT_TRUE(someIpTpPacket1.isPacketOfType(pcpp::SomeIP));
	pcpp::SomeIpTpLayer* someIpTpLayer1 = someIpTpPacket1.getLayerOfType<pcpp::SomeIpTpLayer>();
	PTF_ASSERT_NOT_NULL(someIpTpLayer1);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getHeaderLen(), 1412);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getMessageID(), 0xd05f8001);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getServiceID(), 0xd05f);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getMethodID(), 0x8001);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getLengthField(), 1404);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getRequestID(), 0x0);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getClientID(), 0x0);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getSessionID(), 0x0);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getProtocolVersion(), 1);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getInterfaceVersion(), 0x1);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getMessageType(), pcpp::SomeIpLayer::MsgType::TP_REQUEST_NO_RETURN, enumclass);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::TP_REQUEST_NO_RETURN);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getOffset(), 0);
	PTF_ASSERT_TRUE(someIpTpLayer1->getMoreSegmentsFlag());
	PTF_ASSERT_EQUAL(someIpTpLayer1->getPduPayloadSize(), 1392);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getPduPayload()[0], 0x12);
	PTF_ASSERT_EQUAL(someIpTpLayer1->getPduPayload()[1391], 0x34);
	PTF_ASSERT_EQUAL(someIpTpLayer1->toString(),
	                 "SOME/IP-TP Layer, Service ID: 0xd05f, Method ID: 0x8001, Length: 1404");

	// Test SOME/IP-TP end packet
	PTF_ASSERT_TRUE(someIpTpPacket2.isPacketOfType(pcpp::SomeIP));
	pcpp::SomeIpTpLayer* someIpTpLayer2 = someIpTpPacket2.getLayerOfType<pcpp::SomeIpTpLayer>();
	PTF_ASSERT_NOT_NULL(someIpTpLayer2);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getHeaderLen(), 245);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getMessageID(), 0xd05f8001);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getServiceID(), 0xd05f);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getMethodID(), 0x8001);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getLengthField(), 237);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getRequestID(), 0x0);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getClientID(), 0x0);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getSessionID(), 0x0);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getProtocolVersion(), 1);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getInterfaceVersion(), 0x1);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getMessageType(), pcpp::SomeIpLayer::MsgType::TP_REQUEST_NO_RETURN, enumclass);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::TP_REQUEST_NO_RETURN);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getOffset() * 16, 91872);
	PTF_ASSERT_FALSE(someIpTpLayer2->getMoreSegmentsFlag());
	PTF_ASSERT_EQUAL(someIpTpLayer2->getPduPayloadSize(), 225);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getPduPayload()[0], 0xab);
	PTF_ASSERT_EQUAL(someIpTpLayer2->getPduPayload()[224], 0xcd);
	PTF_ASSERT_EQUAL(someIpTpLayer2->toString(),
	                 "SOME/IP-TP Layer, Service ID: 0xd05f, Method ID: 0x8001, Length: 237");
}

PTF_TEST_CASE(SomeIpTpCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/SomeIpTp1.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/SomeIpTp2.dat");

	const size_t dataLen1 = 1392;
	uint8_t data1[dataLen1] = { 0 };
	data1[0] = 0x12;
	data1[dataLen1 - 1] = 0x34;

	const size_t dataLen2 = 225;
	uint8_t data2[dataLen2] = { 0 };
	data2[0] = 0xab;
	data2[dataLen2 - 1] = 0xcd;

	pcpp::EthLayer ethLayer1(pcpp::MacAddress("02:7d:fa:01:17:40"), pcpp::MacAddress("02:7d:fa:00:10:01"),
	                         PCPP_ETHERTYPE_IP);
	pcpp::IPv4Layer ipLayer1(pcpp::IPv4Address("192.168.0.1"), pcpp::IPv4Address("192.168.0.2"));
	ipLayer1.getIPv4Header()->timeToLive = 20;
	pcpp::UdpLayer udpLayer1(30502, 16832);

	// Test SOME/IP-TP start packet
	pcpp::SomeIpTpLayer someIpTpLayer1(0xd05f, 0x8001, 0, 0, 1, pcpp::SomeIpLayer::MsgType::REQUEST_NO_RETURN, 0, 0,
	                                   true, data1, dataLen1);

	pcpp::Packet someIpTpPacket1(500);
	PTF_ASSERT_TRUE(someIpTpPacket1.addLayer(&ethLayer1));
	PTF_ASSERT_TRUE(someIpTpPacket1.addLayer(&ipLayer1));
	PTF_ASSERT_TRUE(someIpTpPacket1.addLayer(&udpLayer1));
	PTF_ASSERT_TRUE(someIpTpPacket1.addLayer(&someIpTpLayer1));
	someIpTpPacket1.computeCalculateFields();

	PTF_ASSERT_EQUAL(someIpTpPacket1.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(someIpTpPacket1.getRawPacket()->getRawData(), buffer1, bufferLength1);

	// Test SOME/IP-TP end packet
	pcpp::EthLayer ethLayer2(ethLayer1);
	pcpp::IPv4Layer ipLayer2(ipLayer1);
	pcpp::UdpLayer udpLayer2(udpLayer1);
	pcpp::SomeIpTpLayer someIpTpLayer2(0xd05f, 0x8001, 0, 0, 1, pcpp::SomeIpLayer::MsgType::REQUEST_NO_RETURN, 0,
	                                   91872 / 16, false, data2, dataLen2);

	pcpp::Packet someIpTpPacket2(500);
	PTF_ASSERT_TRUE(someIpTpPacket2.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(someIpTpPacket2.addLayer(&ipLayer2));
	PTF_ASSERT_TRUE(someIpTpPacket2.addLayer(&udpLayer2));
	PTF_ASSERT_TRUE(someIpTpPacket2.addLayer(&someIpTpLayer2));
	someIpTpPacket2.computeCalculateFields();

	PTF_ASSERT_EQUAL(someIpTpPacket2.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(someIpTpPacket2.getRawPacket()->getRawData(), buffer2, bufferLength2);

	delete[] buffer1;
	delete[] buffer2;
}

PTF_TEST_CASE(SomeIpTpEditTest)
{
	const size_t dataLen2 = 225;
	uint8_t data2[dataLen2] = { 0 };

	pcpp::SomeIpTpLayer someIpTpLayer(0x6059, 0x410c, 0x3, 0xa, 0x5, pcpp::SomeIpLayer::MsgType::REQUEST, 0, 91872 / 16,
	                                  true, data2, dataLen2);
	someIpTpLayer.setOffset(123);

	PTF_ASSERT_EQUAL(someIpTpLayer.getOffset(), 123);
	PTF_ASSERT_TRUE(someIpTpLayer.getMoreSegmentsFlag());

	someIpTpLayer.setMoreSegmentsFlag(false);

	PTF_ASSERT_EQUAL(someIpTpLayer.getOffset(), 123);
	PTF_ASSERT_FALSE(someIpTpLayer.getMoreSegmentsFlag());
}
