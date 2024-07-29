#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "PPPoELayer.h"
#include "DhcpV6Layer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(PPPoESessionLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/PPPoESession1.dat");

	pcpp::Packet pppoesPacket(&rawPacket1);

	PTF_ASSERT_TRUE(pppoesPacket.isPacketOfType(pcpp::PPPoE));
	PTF_ASSERT_TRUE(pppoesPacket.isPacketOfType(pcpp::PPPoESession));
	pcpp::PPPoESessionLayer* pppoeSessionLayer = pppoesPacket.getLayerOfType<pcpp::PPPoESessionLayer>();
	PTF_ASSERT_NOT_NULL(pppoeSessionLayer);

	PTF_ASSERT_NOT_NULL(pppoeSessionLayer->getPrevLayer());
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPrevLayer()->getProtocol(), pcpp::Ethernet, enum);
	PTF_ASSERT_NOT_NULL(pppoeSessionLayer->getNextLayer());
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);

	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->code, pcpp::PPPoELayer::PPPOE_CODE_SESSION, enum);
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->version, 1);
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->type, 1);
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->sessionId, htobe16(0x0011));
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->payloadLength, htobe16(20));
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPNextProtocol(), PCPP_PPP_LCP);

	PTF_ASSERT_EQUAL(pppoeSessionLayer->toString(),
	                 std::string("PPP-over-Ethernet Session (followed by 'Link Control Protocol')"));
}  // PPPoESessionLayerParsingTest

PTF_TEST_CASE(PPPoESessionLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/PPPoESession2.dat");

	pcpp::Packet samplePacket(&rawPacket1);

	pcpp::EthLayer ethLayer(*samplePacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::PPPoESessionLayer pppoesLayer(1, 1, 0x0011, PCPP_PPP_IPV6);
	pcpp::IPv6Layer ipv6Layer(*samplePacket.getLayerOfType<pcpp::IPv6Layer>());
	pcpp::UdpLayer udpLayer(*samplePacket.getLayerOfType<pcpp::UdpLayer>());
	pcpp::DhcpV6Layer dhcpv6Layer(*samplePacket.getLayerOfType<pcpp::DhcpV6Layer>());

	pcpp::Packet pppoesPacket(1);
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&pppoesLayer));
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&ipv6Layer));
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&udpLayer));
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&dhcpv6Layer));

	pppoesPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(bufferLength1, pppoesPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(pppoesPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);
}  // PPPoESessionLayerCreationTest

PTF_TEST_CASE(PPPoEDiscoveryLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/PPPoEDiscovery2.dat");

	pcpp::Packet pppoedPacket(&rawPacket1);

	PTF_ASSERT_TRUE(pppoedPacket.isPacketOfType(pcpp::PPPoE));
	PTF_ASSERT_TRUE(pppoedPacket.isPacketOfType(pcpp::PPPoEDiscovery));
	PTF_ASSERT_FALSE(pppoedPacket.isPacketOfType(pcpp::PPPoESession));

	pcpp::PPPoEDiscoveryLayer* pppoeDiscoveryLayer = pppoedPacket.getLayerOfType<pcpp::PPPoEDiscoveryLayer>();
	PTF_ASSERT_NOT_NULL(pppoeDiscoveryLayer);

	PTF_ASSERT_NOT_NULL(pppoeDiscoveryLayer->getPrevLayer());
	PTF_ASSERT_NULL(pppoeDiscoveryLayer->getNextLayer());

	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->code, (uint8_t)pcpp::PPPoELayer::PPPOE_CODE_PADS);
	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->version, 1);
	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->type, 1);
	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->sessionId, htobe16(0x0011));
	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->payloadLength, htobe16(40));

	pcpp::PPPoEDiscoveryLayer::PPPoETag firstTag = pppoeDiscoveryLayer->getFirstTag();
	PTF_ASSERT_FALSE(firstTag.isNull());
	PTF_ASSERT_EQUAL(firstTag.getType(), pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_SVC_NAME, enum);
	PTF_ASSERT_EQUAL(firstTag.getDataSize(), 0);

	pcpp::PPPoEDiscoveryLayer::PPPoETag secondTag = pppoeDiscoveryLayer->getNextTag(firstTag);
	PTF_ASSERT_FALSE(secondTag.isNull());
	PTF_ASSERT_EQUAL(secondTag.getType(), pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ, enum);
	PTF_ASSERT_EQUAL(secondTag.getDataSize(), 4);
	PTF_ASSERT_EQUAL(be32toh(secondTag.getValueAs<uint32_t>()), 0x64138518);

	pcpp::PPPoEDiscoveryLayer::PPPoETag thirdTag =
	    pppoeDiscoveryLayer->getTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME);
	PTF_ASSERT_FALSE(thirdTag.isNull());
	PTF_ASSERT_TRUE(thirdTag == pppoeDiscoveryLayer->getNextTag(secondTag));
	PTF_ASSERT_EQUAL(thirdTag.getType(), pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, enum);
	PTF_ASSERT_EQUAL(thirdTag.getDataSize(), 4);
	PTF_ASSERT_EQUAL(thirdTag.getValueAsString(), "BRAS");

	pcpp::PPPoEDiscoveryLayer::PPPoETag fourthTag =
	    pppoeDiscoveryLayer->getTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE);
	PTF_ASSERT_FALSE(fourthTag.isNull());
	PTF_ASSERT_TRUE(fourthTag == pppoeDiscoveryLayer->getNextTag(thirdTag));
	PTF_ASSERT_EQUAL(fourthTag.getType(), pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE, enum);
	PTF_ASSERT_EQUAL(fourthTag.getDataSize(), 16);
	PTF_ASSERT_EQUAL(fourthTag.getValueAs<uint64_t>(), 0xf284240687050f3dULL);
	PTF_ASSERT_EQUAL(fourthTag.getValueAs<uint64_t>(8), 0x5bbd77fdddb932dfULL);
	PTF_ASSERT_TRUE(pppoeDiscoveryLayer->getNextTag(fourthTag).isNull());

	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getTagCount(), 4);

	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->toString(), std::string("PPP-over-Ethernet Discovery (PADS)"));
}  // PPPoEDiscoveryLayerParsingTest

PTF_TEST_CASE(PPPoEDiscoveryLayerCreateTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/PPPoEDiscovery1.dat");

	pcpp::Packet samplePacket(&rawPacket1);

	pcpp::EthLayer ethLayer(*samplePacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::PPPoEDiscoveryLayer pppoedLayer(1, 1, pcpp::PPPoELayer::PPPOE_CODE_PADI, 0);

	pcpp::PPPoEDiscoveryLayer::PPPoETag svcNameTag =
	    pppoedLayer.addTag(pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_SVC_NAME));
	PTF_ASSERT_EQUAL(pppoedLayer.getTagCount(), 1);
	PTF_ASSERT_EQUAL(pppoedLayer.getPPPoEHeader()->payloadLength, htobe16(4));

	uint32_t hostUniqData = 0x64138518;
	pppoedLayer.addTagAfter(
	    pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ, hostUniqData),
	    svcNameTag.getType());
	PTF_ASSERT_EQUAL(pppoedLayer.getTagCount(), 2);
	PTF_ASSERT_EQUAL(pppoedLayer.getPPPoEHeader()->payloadLength, htobe16(12));

	pcpp::Packet pppoedPacket(1);
	PTF_ASSERT_TRUE(pppoedPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(pppoedPacket.addLayer(&pppoedLayer));

	pppoedPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(pppoedPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(pppoedPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	READ_FILE_INTO_BUFFER(2, "PacketExamples/PPPoEDiscovery2.dat");

	pcpp::EthLayer* ethLayerPtr = pppoedPacket.getLayerOfType<pcpp::EthLayer>();
	PTF_ASSERT_NOT_NULL(ethLayerPtr);
	ethLayerPtr->setSourceMac(pcpp::MacAddress("ca:01:0e:88:00:06"));
	ethLayerPtr->setDestMac(pcpp::MacAddress("cc:05:0e:88:00:00"));

	pppoedLayer.getPPPoEHeader()->code = pcpp::PPPoELayer::PPPOE_CODE_PADS;
	pppoedLayer.getPPPoEHeader()->sessionId = htobe16(0x11);

	uint8_t acCookieValue[16] = { 0x3d, 0x0f, 0x05, 0x87, 0x06, 0x24, 0x84, 0xf2,
		                          0xdf, 0x32, 0xb9, 0xdd, 0xfd, 0x77, 0xbd, 0x5b };
	pcpp::PPPoEDiscoveryLayer::PPPoETag acCookieTag = pppoedLayer.addTag(
	    pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE, acCookieValue, 16));
	PTF_ASSERT_EQUAL(pppoedLayer.getTagCount(), 3);
	PTF_ASSERT_EQUAL(pppoedLayer.getPPPoEHeader()->payloadLength, htobe16(32));

	pppoedLayer.addTagAfter(
	    pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HURL, hostUniqData),
	    acCookieTag.getType());
	PTF_ASSERT_EQUAL(pppoedLayer.getTagCount(), 4);
	PTF_ASSERT_EQUAL(pppoedLayer.getPPPoEHeader()->payloadLength, htobe16(40));

	pcpp::PPPoEDiscoveryLayer::PPPoETag hostUniqTag =
	    pppoedLayer.getTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ);
	PTF_ASSERT_FALSE(hostUniqTag.isNull());
	pppoedLayer.addTagAfter(
	    pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, 0x42524153),
	    hostUniqTag.getType());
	PTF_ASSERT_EQUAL(pppoedLayer.getTagCount(), 5);
	PTF_ASSERT_EQUAL(pppoedLayer.getPPPoEHeader()->payloadLength, htobe16(48));

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(pppoedLayer.removeTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_CREDITS));
	pcpp::Logger::getInstance().enableLogs();

	PTF_ASSERT_TRUE(pppoedLayer.removeTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HURL));
	PTF_ASSERT_EQUAL(pppoedLayer.getTagCount(), 4);
	PTF_ASSERT_EQUAL(pppoedLayer.getPPPoEHeader()->payloadLength, htobe16(40));

	PTF_ASSERT_TRUE(pppoedLayer.getTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HURL).isNull());

	pppoedPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(pppoedPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(pppoedPacket.getRawPacket()->getRawData(), buffer2, bufferLength2);

	delete[] buffer2;

	PTF_ASSERT_TRUE(pppoedLayer.removeAllTags());
	pppoedPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(pppoedLayer.getHeaderLen(), sizeof(pcpp::pppoe_header));
	PTF_ASSERT_EQUAL(pppoedLayer.getPPPoEHeader()->payloadLength, 0);
}  // PPPoEDiscoveryLayerCreateTest
