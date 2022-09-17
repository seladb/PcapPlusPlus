#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EthLayer.h"
#include "IPv6Layer.h"
#include "Packet.h"
#include "SomeIpLayer.h"
#include "SystemUtils.h"
#include "UdpLayer.h"
#include "VlanLayer.h"
#include <array>
#include <cstring>

PTF_TEST_CASE(SomeIpParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	// Test adding SOME/IP port and removing with SomeIpLayer::removeAllSomeIpPorts
	pcpp::SomeIpLayer::addSomeIpPort(29180);
	PTF_ASSERT_TRUE(pcpp::SomeIpLayer::isSomeIpPort(29180));
	PTF_ASSERT_FALSE(pcpp::SomeIpLayer::isSomeIpPort(29181));

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/someip.dat");
	pcpp::Packet someIpPacket(&rawPacket1);

	pcpp::SomeIpLayer::removeAllSomeIpPorts();
	PTF_ASSERT_FALSE(pcpp::SomeIpLayer::isSomeIpPort(29180));

	//  Test adding SOME/IP port and removing with SomeIpLayer::removeSomeIpPort
	pcpp::SomeIpLayer::addSomeIpPort(29180);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/someip2.dat");
	pcpp::Packet someIpPacket2(&rawPacket2);

	pcpp::SomeIpLayer::removeSomeIpPort(29180);
	PTF_ASSERT_FALSE(pcpp::SomeIpLayer::isSomeIpPort(29180));

	// Test with one SOME/IP layer
	PTF_ASSERT_TRUE(someIpPacket.isPacketOfType(pcpp::SomeIP));
	pcpp::SomeIpLayer *someIpLayer = someIpPacket.getLayerOfType<pcpp::SomeIpLayer>();
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
	PTF_ASSERT_EQUAL((int)someIpLayer->getMessageType(), (int)pcpp::SomeIpLayer::MsgType::REQUEST);
	PTF_ASSERT_EQUAL(someIpLayer->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::REQUEST);
	PTF_ASSERT_EQUAL(someIpLayer->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpLayer->getPduPayloadSize(), 22);
	PTF_ASSERT_EQUAL(someIpLayer->getPduPayload()[0], 0x40);
	PTF_ASSERT_EQUAL(someIpLayer->getPduPayload()[20], 0x01);
	PTF_ASSERT_EQUAL(someIpLayer->toString(), "SOME/IP Layer, Service ID: 0x6059, Method ID: 0x410c, Length: 30");
	PTF_ASSERT_NULL(someIpLayer->getNextLayer());

	// Test with two SOME/IP layers
	pcpp::SomeIpLayer *someIpLayer2_1 = someIpPacket2.getLayerOfType<pcpp::SomeIpLayer>();
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
	PTF_ASSERT_EQUAL((int)someIpLayer2_1->getMessageType(), (int)pcpp::SomeIpLayer::MsgType::REQUEST);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getMessageTypeAsInt(), (uint8_t)pcpp::SomeIpLayer::MsgType::REQUEST);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getReturnCode(), 0);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getPduPayloadSize(), 22);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getPduPayload()[0], 0x40);
	PTF_ASSERT_EQUAL(someIpLayer2_1->getPduPayload()[20], 0x01);
	PTF_ASSERT_EQUAL(someIpLayer2_1->toString(), "SOME/IP Layer, Service ID: 0x6059, Method ID: 0x410c, Length: 30");
	PTF_ASSERT_NOT_NULL(someIpLayer2_1->getNextLayer());

	pcpp::SomeIpLayer *someIpLayer2_2 =  someIpPacket2.getNextLayerOfType<pcpp::SomeIpLayer>(someIpLayer2_1);
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
	PTF_ASSERT_EQUAL((int)someIpLayer2_2->getMessageType(), (int)pcpp::SomeIpLayer::MsgType::REQUEST);
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
	gettimeofday(&time, NULL);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/someip.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/someip2.dat");

	std::array<uint8_t, 22> data1{0x40, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								  0x00, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00};

	std::array<uint8_t, 20> data2{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
								  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14};

	// Test with one SOME/IP layer
	pcpp::SomeIpLayer someipLayer1(0x6059, 0x410c, 0x3, 0xa, 0x5, pcpp::SomeIpLayer::MsgType::REQUEST, 0, data1.data(), data1.size());
	pcpp::Packet someIpPacket(100);
	PTF_ASSERT_TRUE(someIpPacket.addLayer(&someipLayer1));
	someIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(someIpPacket.getRawPacket()->getRawDataLen(), bufferLength1-78);
	PTF_ASSERT_BUF_COMPARE(someIpPacket.getRawPacket()->getRawData(), buffer1+78, bufferLength1-78);

	// Test with two SOME/IP layers
	pcpp::EthLayer ethLayer2(pcpp::MacAddress("02:7d:fa:01:17:40"), pcpp::MacAddress("02:7d:fa:00:10:01"), PCPP_ETHERTYPE_VLAN);
	pcpp::VlanLayer vlanLayer2(2, false, 0, PCPP_ETHERTYPE_IP);
	pcpp::IPv6Layer ip6Layer2(pcpp::IPv6Address("fd53:7cb8:0383:0002::0001:0117"), pcpp::IPv6Address("fd53:7cb8:0383:000e::0014"));
	pcpp::UdpLayer udpLayer2(29300, 29180);
	pcpp::SomeIpLayer someipLayer2_1(0x6059, 0x410c, 0x3, 0xa, 0x5, pcpp::SomeIpLayer::MsgType::REQUEST, 0, data1.data(), data1.size());
	pcpp::SomeIpLayer someipLayer2_2(0x6060, 0x410d, 0x4, 0xb, 0x6, pcpp::SomeIpLayer::MsgType::REQUEST, 0, data2.data(), data2.size());

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

	delete [] buffer1;
	delete [] buffer2;
}
