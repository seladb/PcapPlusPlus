#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "IPSecLayer.h"
#include "SystemUtils.h"


PTF_TEST_CASE(IPSecParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ipsec_ah_esp.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ipsec_ah_icmp.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/ipsec_esp_ipv6.dat");

	pcpp::Packet ipsec1Packet(&rawPacket1);
	pcpp::Packet ipsec2Packet(&rawPacket2);
	pcpp::Packet ipsec3Packet(&rawPacket3);

	PTF_ASSERT_TRUE(ipsec1Packet.isPacketOfType(pcpp::IPSec));
	PTF_ASSERT_TRUE(ipsec2Packet.isPacketOfType(pcpp::IPSec));
	PTF_ASSERT_TRUE(ipsec3Packet.isPacketOfType(pcpp::IPSec));
	PTF_ASSERT_TRUE(ipsec1Packet.isPacketOfType(pcpp::AuthenticationHeader));
	PTF_ASSERT_TRUE(ipsec1Packet.isPacketOfType(pcpp::ESP));
	PTF_ASSERT_TRUE(ipsec2Packet.isPacketOfType(pcpp::AuthenticationHeader));
	PTF_ASSERT_TRUE(ipsec2Packet.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_TRUE(ipsec3Packet.isPacketOfType(pcpp::ESP));

	pcpp::AuthenticationHeaderLayer* ahLayer = ipsec1Packet.getLayerOfType<pcpp::AuthenticationHeaderLayer>();
	PTF_ASSERT_NOT_NULL(ahLayer);
	PTF_ASSERT_EQUAL(ahLayer->getSPI(), 0x8179b705, u32);
	PTF_ASSERT_EQUAL(ahLayer->getSequenceNumber(), 3, u32);
	PTF_ASSERT_EQUAL(ahLayer->getICVLength(), 12, size);
	PTF_ASSERT_EQUAL(ahLayer->getICVHexStream(), "62325d2ea14e86ab902b70fb", string);
	PTF_ASSERT_EQUAL(ahLayer->getHeaderLen(), 24, size);
	PTF_ASSERT_EQUAL(ahLayer->toString(), "Authentication Header Layer", string);
	PTF_ASSERT_EQUAL(ahLayer->getNextLayer()->getProtocol(), pcpp::ESP, u64);

	pcpp::ESPLayer* espLayer = ipsec1Packet.getLayerOfType<pcpp::ESPLayer>();
	PTF_ASSERT_NOT_NULL(espLayer);
	PTF_ASSERT_EQUAL(espLayer->getSPI(), 0x48dac2e4, u32);
	PTF_ASSERT_EQUAL(espLayer->getSequenceNumber(), 3, u32);
	PTF_ASSERT_EQUAL(espLayer->getHeaderLen(), 8, size);
	PTF_ASSERT_EQUAL(espLayer->toString(), "ESP Layer, SPI: 0x48dac2e4", string);
	PTF_ASSERT_EQUAL(espLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload, u64);

	ahLayer = ipsec2Packet.getLayerOfType<pcpp::AuthenticationHeaderLayer>();
	PTF_ASSERT_NOT_NULL(ahLayer);
	PTF_ASSERT_EQUAL(ahLayer->getSPI(), 0x646adc80, u32);
	PTF_ASSERT_EQUAL(ahLayer->getSequenceNumber(), 8, u32);
	PTF_ASSERT_EQUAL(ahLayer->getICVLength(), 12, size);
	PTF_ASSERT_EQUAL(ahLayer->getICVHexStream(), "03d9ebccbbc8d14cccb87ade", string);
	PTF_ASSERT_EQUAL(ahLayer->getHeaderLen(), 24, size);
	PTF_ASSERT_EQUAL(ahLayer->getNextLayer()->getProtocol(), pcpp::IPv4, u64);

	espLayer = ipsec3Packet.getLayerOfType<pcpp::ESPLayer>();
	PTF_ASSERT_NOT_NULL(espLayer);
	PTF_ASSERT_EQUAL(espLayer->getSPI(), 0x49507636, u32);
	PTF_ASSERT_EQUAL(espLayer->getSequenceNumber(), 541414224, u32);
} // IPSecParsingTest
