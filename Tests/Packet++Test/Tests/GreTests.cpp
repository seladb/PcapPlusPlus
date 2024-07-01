#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "EthLayer.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PPPoELayer.h"
#include "GreLayer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include "SystemUtils.h"

PTF_TEST_CASE(GreParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/GREv0_1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/GREv0_2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/GREv1_1.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/GREv1_2.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/GREv0_4.dat");

	pcpp::GREv0Layer* grev0Layer = nullptr;
	pcpp::GREv1Layer* grev1Layer = nullptr;
	pcpp::TcpLayer* tcpLayer = nullptr;

	pcpp::Packet grev0Packet1(&rawPacket1);
	pcpp::Packet grev0Packet2(&rawPacket2);
	pcpp::Packet grev1Packet1(&rawPacket3);
	pcpp::Packet grev1Packet2(&rawPacket4);
	pcpp::Packet grev0Packet4(&rawPacket5);

	uint16_t value16 = 0;
	uint32_t value32 = 0;

	// GREv0 packet 1
	PTF_ASSERT_TRUE(grev0Packet1.isPacketOfType(pcpp::GRE) && grev0Packet1.isPacketOfType(pcpp::GREv0));
	grev0Layer = grev0Packet1.getLayerOfType<pcpp::GREv0Layer>();
	PTF_ASSERT_NOT_NULL(grev0Layer);
	PTF_ASSERT_EQUAL(grev0Layer->getHeaderLen(), 8);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->checksumBit, 1);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->routingBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->ackSequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->sequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->recursionControl, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->flags, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->protocol, htobe16(PCPP_ETHERTYPE_IP));
	PTF_ASSERT_TRUE(grev0Layer->getChecksum(value16));
	PTF_ASSERT_EQUAL(value16, 30719);
	value16 = 40000;
	value32 = 40000;
	PTF_ASSERT_FALSE(grev0Layer->getOffset(value16));
	PTF_ASSERT_EQUAL(value16, 40000);
	PTF_ASSERT_FALSE(grev0Layer->getKey(value32));
	PTF_ASSERT_EQUAL(value32, 40000);
	PTF_ASSERT_FALSE(grev0Layer->getSequenceNumber(value32));
	PTF_ASSERT_EQUAL(value32, 40000);
	PTF_ASSERT_NOT_NULL(grev0Layer->getNextLayer());
	PTF_ASSERT_EQUAL(grev0Layer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	grev0Layer = nullptr;

	// GREv0 packet 2
	PTF_ASSERT_TRUE(grev0Packet2.isPacketOfType(pcpp::GRE) && grev0Packet2.isPacketOfType(pcpp::GREv0));
	grev0Layer = grev0Packet2.getLayerOfType<pcpp::GREv0Layer>();
	PTF_ASSERT_NOT_NULL(grev0Layer);
	PTF_ASSERT_EQUAL(grev0Layer->getHeaderLen(), 4);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->checksumBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->sequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->recursionControl, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->protocol, htobe16(PCPP_ETHERTYPE_IP));
	value16 = 40000;
	value32 = 40000;
	PTF_ASSERT_FALSE(grev0Layer->getChecksum(value16));
	PTF_ASSERT_EQUAL(value16, 40000);
	PTF_ASSERT_FALSE(grev0Layer->getKey(value32));
	PTF_ASSERT_EQUAL(value32, 40000);
	PTF_ASSERT_NOT_NULL(grev0Layer->getNextLayer());
	PTF_ASSERT_EQUAL(grev0Layer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	grev0Layer = grev0Packet2.getNextLayerOfType<pcpp::GREv0Layer>(grev0Layer);
	PTF_ASSERT_NOT_NULL(grev0Layer);
	PTF_ASSERT_EQUAL(grev0Layer->getHeaderLen(), 4);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->checksumBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->sequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->recursionControl, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->protocol, htobe16(PCPP_ETHERTYPE_IP));
	PTF_ASSERT_NOT_NULL(grev0Layer->getNextLayer());
	PTF_ASSERT_EQUAL(grev0Layer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	grev0Layer = nullptr;

	// GREv1 packet 1
	PTF_ASSERT_TRUE(grev1Packet1.isPacketOfType(pcpp::GRE) && grev1Packet1.isPacketOfType(pcpp::GREv1));
	grev1Layer = grev1Packet1.getLayerOfType<pcpp::GREv1Layer>();
	PTF_ASSERT_NOT_NULL(grev1Layer);
	PTF_ASSERT_EQUAL(grev1Layer->getHeaderLen(), 12);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->checksumBit, 0);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->sequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->keyBit, 1);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->ackSequenceNumBit, 1);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->callID, htobe16(6));
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->payloadLength, 0);
	value32 = 40000;
	PTF_ASSERT_FALSE(grev1Layer->getSequenceNumber(value32));
	PTF_ASSERT_EQUAL(value32, 40000);
	PTF_ASSERT_TRUE(grev1Layer->getAcknowledgmentNum(value32));
	PTF_ASSERT_EQUAL(value32, 26);
	PTF_ASSERT_NULL(grev1Layer->getNextLayer());
	grev1Layer = nullptr;

	// GREv1 packet 2
	PTF_ASSERT_TRUE(grev1Packet2.isPacketOfType(pcpp::GRE) && grev1Packet2.isPacketOfType(pcpp::GREv1));
	PTF_ASSERT_TRUE(grev1Packet2.isPacketOfType(pcpp::PPP_PPTP));
	grev1Layer = grev1Packet2.getLayerOfType<pcpp::GREv1Layer>();
	PTF_ASSERT_NOT_NULL(grev1Layer);
	PTF_ASSERT_EQUAL(grev1Layer->getHeaderLen(), 12);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->checksumBit, 0);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->routingBit, 0);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->sequenceNumBit, 1);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->keyBit, 1);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->ackSequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->callID, htobe16(17));
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->payloadLength, htobe16(178));
	value32 = 40000;
	PTF_ASSERT_FALSE(grev1Layer->getAcknowledgmentNum(value32));
	PTF_ASSERT_EQUAL(value32, 40000);
	PTF_ASSERT_TRUE(grev1Layer->getSequenceNumber(value32));
	PTF_ASSERT_EQUAL(value32, 539320);
	PTF_ASSERT_NOT_NULL(grev1Layer->getNextLayer());
	PTF_ASSERT_EQUAL(grev1Layer->getNextLayer()->getProtocol(), pcpp::PPP_PPTP, enum);
	pcpp::PPP_PPTPLayer* pppLayer = grev1Packet2.getLayerOfType<pcpp::PPP_PPTPLayer>();
	PTF_ASSERT_NOT_NULL(pppLayer);
	PTF_ASSERT_EQUAL(pppLayer->getHeaderLen(), 4);
	PTF_ASSERT_EQUAL(pppLayer, grev1Layer->getNextLayer(), ptr);
	PTF_ASSERT_EQUAL(pppLayer->getPPP_PPTPHeader()->address, 0xff);
	PTF_ASSERT_EQUAL(pppLayer->getPPP_PPTPHeader()->control, 3);
	PTF_ASSERT_EQUAL(pppLayer->getPPP_PPTPHeader()->protocol, htobe16(PCPP_PPP_IP));
	PTF_ASSERT_NOT_NULL(pppLayer->getNextLayer());
	PTF_ASSERT_EQUAL(pppLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	grev1Layer = nullptr;

	// GREv0 packet 4 - Transparent Ethernet Bridging
	PTF_ASSERT_TRUE(grev0Packet4.isPacketOfType(pcpp::GRE) && grev0Packet4.isPacketOfType(pcpp::GREv0));
	grev0Layer = grev0Packet4.getLayerOfType<pcpp::GREv0Layer>();
	PTF_ASSERT_NOT_NULL(grev0Layer);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->keyBit, 1);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->protocol, htobe16(PCPP_ETHERTYPE_ETHBRIDGE));
	PTF_ASSERT_TRUE(grev0Layer->getKey(value32));
	PTF_ASSERT_EQUAL(value32, 0xFDE8);
	// to ensure it parsed through GRE to next layers, find tcp from bottom
	tcpLayer = grev0Packet4.getLayerOfType<pcpp::TcpLayer>(true /* reverse */);
	PTF_ASSERT_NOT_NULL(tcpLayer);
	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), 1232);
	grev0Layer = nullptr;
	tcpLayer = nullptr;
}  // GreParsingTest

PTF_TEST_CASE(GreCreationTest)
{
	READ_FILE_INTO_BUFFER(1, "PacketExamples/GREv1_3.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/GREv0_3.dat");

	// GREv1 packet creation

	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:90:4b:1f:a4:f7"), pcpp::MacAddress("00:0d:ed:7b:48:f4"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("192.168.2.65"), pcpp::IPv4Address("192.168.2.254"));
	ipLayer.getIPv4Header()->ipId = htobe16(1660);
	ipLayer.getIPv4Header()->timeToLive = 128;

	pcpp::GREv1Layer grev1Layer(6);

	pcpp::PPP_PPTPLayer pppLayer(0xff, 3);
	pppLayer.getPPP_PPTPHeader()->protocol = htobe16(PCPP_PPP_CCP);

	uint8_t data[4] = { 0x06, 0x04, 0x00, 0x04 };
	pcpp::PayloadLayer payloadLayer(data, 4);

	pcpp::Packet grev1Packet(1);
	PTF_ASSERT_TRUE(grev1Packet.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(grev1Packet.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(grev1Packet.addLayer(&grev1Layer));
	PTF_ASSERT_TRUE(grev1Packet.addLayer(&pppLayer));
	PTF_ASSERT_TRUE(grev1Packet.addLayer(&payloadLayer));

	PTF_ASSERT_TRUE(grev1Layer.setAcknowledgmentNum(17));
	PTF_ASSERT_TRUE(grev1Layer.setSequenceNumber(34));

	grev1Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev1Packet.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(grev1Packet.getRawPacket()->getRawData(), buffer1, bufferLength1);

	// GREv0 packet creation

	pcpp::EthLayer ethLayer2(pcpp::MacAddress("00:01:01:00:00:01"), pcpp::MacAddress("00:01:01:00:00:02"));
	pcpp::IPv4Layer ipLayer2(pcpp::IPv4Address("127.0.0.1"), pcpp::IPv4Address("127.0.0.1"));
	ipLayer2.getIPv4Header()->ipId = htobe16(1);
	ipLayer2.getIPv4Header()->timeToLive = 64;
	pcpp::IPv4Layer ipLayer3(pcpp::IPv4Address("127.0.0.1"), pcpp::IPv4Address("127.0.0.1"));
	ipLayer3.getIPv4Header()->ipId = htobe16(46845);
	ipLayer3.getIPv4Header()->timeToLive = 64;

	pcpp::GREv0Layer grev0Layer1;
	PTF_ASSERT_TRUE(grev0Layer1.setChecksum(1));

	pcpp::GREv0Layer grev0Layer2;

	pcpp::Packet grev0Packet(12);
	PTF_ASSERT_TRUE(grev0Packet.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(grev0Packet.addLayer(&ipLayer2));
	PTF_ASSERT_TRUE(grev0Packet.addLayer(&grev0Layer1));
	PTF_ASSERT_TRUE(grev0Packet.addLayer(&ipLayer3));
	PTF_ASSERT_TRUE(grev0Packet.addLayer(&grev0Layer2));
	grev0Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev0Packet.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(grev0Packet.getRawPacket()->getRawData(), buffer2, bufferLength2);

	delete[] buffer1;
	delete[] buffer2;
}  // GreCreationTest

PTF_TEST_CASE(GreEditTest)
{
	// GREv0 packet edit

	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/GREv0_3.dat");

	pcpp::Packet grev0Packet(&rawPacket1);

	PTF_ASSERT_TRUE(grev0Packet.isPacketOfType(pcpp::GRE) && grev0Packet.isPacketOfType(pcpp::GREv0));
	pcpp::GREv0Layer* grev0Layer = grev0Packet.getLayerOfType<pcpp::GREv0Layer>();
	PTF_ASSERT_NOT_NULL(grev0Layer);
	PTF_ASSERT_TRUE(grev0Layer->setSequenceNumber(1234));
	PTF_ASSERT_TRUE(grev0Layer->setKey(2341));
	grev0Packet.computeCalculateFields();

	uint16_t value16 = 0;
	uint32_t value32 = 0;
	grev0Layer = grev0Packet.getLayerOfType<pcpp::GREv0Layer>();
	PTF_ASSERT_NOT_NULL(grev0Layer);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->checksumBit, 1);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->sequenceNumBit, 1);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->keyBit, 1);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->strictSourceRouteBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->routingBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getHeaderLen(), 16);
	PTF_ASSERT_TRUE(grev0Layer->getChecksum(value16));
	PTF_ASSERT_EQUAL(value16, 14856);
	PTF_ASSERT_TRUE(grev0Layer->getSequenceNumber(value32));
	PTF_ASSERT_EQUAL(value32, 1234);
	PTF_ASSERT_TRUE(grev0Layer->getKey(value32));
	PTF_ASSERT_EQUAL(value32, 2341);
	PTF_ASSERT_FALSE(grev0Layer->getOffset(value16));
	grev0Layer->getGreHeader()->routingBit = 1;
	PTF_ASSERT_TRUE(grev0Layer->getOffset(value16));
	PTF_ASSERT_EQUAL(value16, 0);
	grev0Layer->getGreHeader()->routingBit = 0;

	PTF_ASSERT_TRUE(grev0Layer->setSequenceNumber(5678));
	grev0Packet.computeCalculateFields();

	PTF_ASSERT_TRUE(grev0Layer->getSequenceNumber(value32));
	PTF_ASSERT_EQUAL(value32, 5678);
	PTF_ASSERT_TRUE(grev0Layer->getChecksum(value16));
	PTF_ASSERT_EQUAL(value16, 10412);
	PTF_ASSERT_TRUE(grev0Layer->getKey(value32));
	PTF_ASSERT_EQUAL(value32, 2341);

	PTF_ASSERT_TRUE(grev0Layer->unsetSequenceNumber());
	grev0Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->sequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getHeaderLen(), 12);
	PTF_ASSERT_FALSE(grev0Layer->getSequenceNumber(value32));
	PTF_ASSERT_TRUE(grev0Layer->getKey(value32));
	PTF_ASSERT_EQUAL(value32, 2341);
	PTF_ASSERT_TRUE(grev0Layer->getChecksum(value16));
	PTF_ASSERT_EQUAL(value16, 20186);

	PTF_ASSERT_TRUE(grev0Layer->unsetChecksum());
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(grev0Layer->unsetSequenceNumber());
	pcpp::Logger::getInstance().enableLogs();
	grev0Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->checksumBit, 0);
	PTF_ASSERT_TRUE(!grev0Layer->getChecksum(value16));
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->sequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getHeaderLen(), 8);
	PTF_ASSERT_FALSE(grev0Layer->getSequenceNumber(value32));
	PTF_ASSERT_TRUE(grev0Layer->getKey(value32));
	PTF_ASSERT_EQUAL(value32, 2341);

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(grev0Layer->unsetChecksum());
	PTF_ASSERT_FALSE(grev0Layer->unsetSequenceNumber());
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_TRUE(grev0Layer->unsetKey());
	grev0Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->keyBit, 0);
	PTF_ASSERT_FALSE(grev0Layer->getKey(value32));
	PTF_ASSERT_EQUAL(grev0Layer->getHeaderLen(), 4);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->checksumBit, 0);
	PTF_ASSERT_FALSE(grev0Layer->getChecksum(value16));
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->sequenceNumBit, 0);

	PTF_ASSERT_TRUE(grev0Layer->setChecksum(0));
	grev0Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->checksumBit, 1);
	PTF_ASSERT_EQUAL(grev0Layer->getHeaderLen(), 8);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->keyBit, 0);
	PTF_ASSERT_EQUAL(grev0Layer->getGreHeader()->sequenceNumBit, 0);
	PTF_ASSERT_TRUE(grev0Layer->getChecksum(value16));
	PTF_ASSERT_EQUAL(value16, 30719);

	// GREv1 packet edit

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/GREv1_2.dat");

	pcpp::Packet grev1Packet(&rawPacket2);

	value16 = 0;
	value32 = 0;
	pcpp::GREv1Layer* grev1Layer = grev1Packet.getLayerOfType<pcpp::GREv1Layer>();
	PTF_ASSERT_TRUE(grev1Layer->setAcknowledgmentNum(56789));
	grev1Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev1Layer->getHeaderLen(), 16);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->ackSequenceNumBit, 1);
	PTF_ASSERT_TRUE(grev1Layer->getAcknowledgmentNum(value32));
	PTF_ASSERT_EQUAL(value32, 56789);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->keyBit, 1);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->checksumBit, 0);
	PTF_ASSERT_TRUE(grev1Layer->getSequenceNumber(value32));
	PTF_ASSERT_EQUAL(value32, 539320);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->callID, htobe16(17));
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->payloadLength, htobe16(178));

	PTF_ASSERT_TRUE(grev1Layer->setSequenceNumber(12345));
	grev1Layer->getGreHeader()->callID = htobe16(123);
	grev1Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev1Layer->getHeaderLen(), 16);
	PTF_ASSERT_TRUE(grev1Layer->getSequenceNumber(value32));
	PTF_ASSERT_EQUAL(value32, 12345);
	PTF_ASSERT_TRUE(grev1Layer->getAcknowledgmentNum(value32));
	PTF_ASSERT_EQUAL(value32, 56789);

	PTF_ASSERT_TRUE(grev1Layer->unsetSequenceNumber());
	grev1Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev1Layer->getHeaderLen(), 12);
	PTF_ASSERT_FALSE(grev1Layer->getSequenceNumber(value32));
	PTF_ASSERT_TRUE(grev1Layer->getAcknowledgmentNum(value32));
	PTF_ASSERT_EQUAL(value32, 56789);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->callID, htobe16(123));
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->payloadLength, htobe16(178));

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(grev0Layer->unsetSequenceNumber());
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_TRUE(grev1Layer->unsetAcknowledgmentNum());
	grev1Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(grev1Layer->getHeaderLen(), 8);
	PTF_ASSERT_FALSE(grev1Layer->getAcknowledgmentNum(value32));
	PTF_ASSERT_FALSE(grev1Layer->getSequenceNumber(value32));
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->ackSequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->sequenceNumBit, 0);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->keyBit, 1);
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->callID, htobe16(123));
	PTF_ASSERT_EQUAL(grev1Layer->getGreHeader()->payloadLength, htobe16(178));

	PTF_ASSERT_NOT_NULL(grev1Layer->getNextLayer());
	PTF_ASSERT_EQUAL(grev1Layer->getNextLayer()->getProtocol(), pcpp::PPP_PPTP, enum);
	pcpp::PPP_PPTPLayer* pppLayer = dynamic_cast<pcpp::PPP_PPTPLayer*>(grev1Layer->getNextLayer());
	PTF_ASSERT_NOT_NULL(pppLayer);
	pppLayer->getPPP_PPTPHeader()->control = 255;

	PTF_ASSERT_TRUE(grev1Packet.removeAllLayersAfter(pppLayer));

	grev1Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(pppLayer->getPPP_PPTPHeader()->protocol, 0);

	auto ipv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("2402:f000:1:8e01::5555"),
	                                     pcpp::IPv6Address("2607:fcd0:100:2300::b108:2a6b"));
	PTF_ASSERT_TRUE(grev1Packet.addLayer(ipv6Layer, true));
	grev1Packet.computeCalculateFields();

	PTF_ASSERT_NOT_NULL(pppLayer->getNextLayer());
	PTF_ASSERT_EQUAL(pppLayer->getNextLayer()->getProtocol(), pcpp::IPv6, enum);
	PTF_ASSERT_EQUAL(pppLayer->getPPP_PPTPHeader()->protocol, htobe16(PCPP_PPP_IPV6));
}  // GreEditTest
