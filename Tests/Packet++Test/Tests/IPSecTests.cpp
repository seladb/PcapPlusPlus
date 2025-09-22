#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "IPSecLayer.h"
#include "SystemUtils.h"

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(IPSecParsingTest)
{
	auto rawPacket1 = createPacketFromHexResource("PacketExamples/ipsec_ah_esp.dat");
	auto rawPacket2 = createPacketFromHexResource("PacketExamples/ipsec_ah_icmp.dat");
	auto rawPacket3 = createPacketFromHexResource("PacketExamples/ipsec_esp_ipv6.dat");

	pcpp::Packet ipsec1Packet(rawPacket1.get());
	pcpp::Packet ipsec2Packet(rawPacket2.get());
	pcpp::Packet ipsec3Packet(rawPacket3.get());

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
	PTF_ASSERT_EQUAL(ahLayer->getSPI(), 0x8179b705);
	PTF_ASSERT_EQUAL(ahLayer->getSequenceNumber(), 3);
	PTF_ASSERT_EQUAL(ahLayer->getICVLength(), 12);
	PTF_ASSERT_EQUAL(ahLayer->getICVHexStream(), "62325d2ea14e86ab902b70fb");
	PTF_ASSERT_EQUAL(ahLayer->getHeaderLen(), 24);
	PTF_ASSERT_EQUAL(ahLayer->toString(), "Authentication Header Layer");
	PTF_ASSERT_EQUAL(ahLayer->getNextLayer()->getProtocol(), pcpp::ESP, enum);

	pcpp::ESPLayer* espLayer = ipsec1Packet.getLayerOfType<pcpp::ESPLayer>();
	PTF_ASSERT_NOT_NULL(espLayer);
	PTF_ASSERT_EQUAL(espLayer->getSPI(), 0x48dac2e4);
	PTF_ASSERT_EQUAL(espLayer->getSequenceNumber(), 3);
	PTF_ASSERT_EQUAL(espLayer->getHeaderLen(), 8);
	PTF_ASSERT_EQUAL(espLayer->toString(), "ESP Layer, SPI: 0x48dac2e4");
	PTF_ASSERT_EQUAL(espLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);

	ahLayer = ipsec2Packet.getLayerOfType<pcpp::AuthenticationHeaderLayer>();
	PTF_ASSERT_NOT_NULL(ahLayer);
	PTF_ASSERT_EQUAL(ahLayer->getSPI(), 0x646adc80);
	PTF_ASSERT_EQUAL(ahLayer->getSequenceNumber(), 8);
	PTF_ASSERT_EQUAL(ahLayer->getICVLength(), 12);
	PTF_ASSERT_EQUAL(ahLayer->getICVHexStream(), "03d9ebccbbc8d14cccb87ade");
	PTF_ASSERT_EQUAL(ahLayer->getHeaderLen(), 24);
	PTF_ASSERT_EQUAL(ahLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);

	espLayer = ipsec3Packet.getLayerOfType<pcpp::ESPLayer>();
	PTF_ASSERT_NOT_NULL(espLayer);
	PTF_ASSERT_EQUAL(espLayer->getSPI(), 0x49507636);
	PTF_ASSERT_EQUAL(espLayer->getSequenceNumber(), 541414224);
}  // IPSecParsingTest
