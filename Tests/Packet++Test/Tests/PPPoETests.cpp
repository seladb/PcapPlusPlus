#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "PPPoELayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"


PTF_TEST_CASE(PPPoESessionLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/PPPoESession1.dat");

	pcpp::Packet pppoesPacket(&rawPacket1);

	PTF_ASSERT_TRUE(pppoesPacket.isPacketOfType(pcpp::PPPoE));
	PTF_ASSERT_TRUE(pppoesPacket.isPacketOfType(pcpp::PPPoESession));
	pcpp::PPPoESessionLayer* pppoeSessionLayer = pppoesPacket.getLayerOfType<pcpp::PPPoESessionLayer>();
	PTF_ASSERT_NOT_NULL(pppoeSessionLayer);

	PTF_ASSERT_NOT_NULL(pppoeSessionLayer->getPrevLayer());
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPrevLayer()->getProtocol(), pcpp::Ethernet, u64);
	PTF_ASSERT_NOT_NULL(pppoeSessionLayer->getNextLayer());
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload, u64);

	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->code, pcpp::PPPoELayer::PPPOE_CODE_SESSION, enum);
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->version, 1, u8);
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->type, 1, u8);
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->sessionId, htobe16(0x0011), u16);
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPoEHeader()->payloadLength, htobe16(20), u16);
	PTF_ASSERT_EQUAL(pppoeSessionLayer->getPPPNextProtocol(), PCPP_PPP_LCP, u16);

	PTF_ASSERT_EQUAL(pppoeSessionLayer->toString(), std::string("PPP-over-Ethernet Session (followed by 'Link Control Protocol')"), string);
} // PPPoESessionLayerParsingTest



PTF_TEST_CASE(PPPoESessionLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/PPPoESession2.dat");

	pcpp::Packet samplePacket(&rawPacket1);

	pcpp::Packet pppoesPacket(1);

	pcpp::EthLayer ethLayer(*samplePacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&ethLayer));

	pcpp::PPPoESessionLayer pppoesLayer(1, 1, 0x0011, PCPP_PPP_IPV6);
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&pppoesLayer));

	pcpp::IPv6Layer ipv6Layer(*samplePacket.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&ipv6Layer));

	pcpp::UdpLayer udpLayer(*samplePacket.getLayerOfType<pcpp::UdpLayer>());
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&udpLayer));

	pcpp::PayloadLayer payloadLayer(*samplePacket.getLayerOfType<pcpp::PayloadLayer>());
	PTF_ASSERT_TRUE(pppoesPacket.addLayer(&payloadLayer));

	pppoesPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(bufferLength1, pppoesPacket.getRawPacket()->getRawDataLen(), int);
	PTF_ASSERT_BUF_COMPARE(pppoesPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);
} // PPPoESessionLayerCreationTest



PTF_TEST_CASE(PPPoEDiscoveryLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/PPPoEDiscovery2.dat");

	pcpp::Packet pppoedPacket(&rawPacket1);

	PTF_ASSERT_TRUE(pppoedPacket.isPacketOfType(pcpp::PPPoE));
	PTF_ASSERT_TRUE(pppoedPacket.isPacketOfType(pcpp::PPPoEDiscovery));
	PTF_ASSERT_FALSE(pppoedPacket.isPacketOfType(pcpp::PPPoESession));

	pcpp::PPPoEDiscoveryLayer* pppoeDiscoveryLayer = pppoedPacket.getLayerOfType<pcpp::PPPoEDiscoveryLayer>();
	PTF_ASSERT_NOT_NULL(pppoeDiscoveryLayer);

	PTF_ASSERT_NOT_NULL(pppoeDiscoveryLayer->getPrevLayer());
	PTF_ASSERT_NULL(pppoeDiscoveryLayer->getNextLayer());

	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->code, (uint8_t)pcpp::PPPoELayer::PPPOE_CODE_PADS, u8);
	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->version, 1, u8);
	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->type, 1, u8);
	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->sessionId, htobe16(0x0011), u16);
	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getPPPoEHeader()->payloadLength, htobe16(40), u16);

	pcpp::PPPoEDiscoveryLayer::PPPoETag* firstTag = pppoeDiscoveryLayer->getFirstTag();
	PTF_ASSERT_NOT_NULL(firstTag);
	PTF_ASSERT_EQUAL(firstTag->getType(), pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_SVC_NAME, enum);
	PTF_ASSERT_EQUAL(firstTag->tagDataLength, 0, u16);

	pcpp::PPPoEDiscoveryLayer::PPPoETag* secondTag = pppoeDiscoveryLayer->getNextTag(firstTag);
	PTF_ASSERT_NOT_NULL(secondTag);
	PTF_ASSERT_EQUAL(secondTag->getType(), pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ, enum);
	PTF_ASSERT_EQUAL(secondTag->tagDataLength, htobe16(4), u16);
	PTF_ASSERT_EQUAL(be32toh(secondTag->getTagDataAs<uint32_t>()), 0x64138518, u32);

	pcpp::PPPoEDiscoveryLayer::PPPoETag* thirdTag = pppoeDiscoveryLayer->getTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME);
	PTF_ASSERT_NOT_NULL(thirdTag);
	PTF_ASSERT_TRUE(thirdTag == pppoeDiscoveryLayer->getNextTag(secondTag));
	PTF_ASSERT_EQUAL(thirdTag->getType(), pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, enum);
	PTF_ASSERT_EQUAL(thirdTag->tagDataLength, htobe16(4), u16);
	PTF_ASSERT_EQUAL(be32toh(thirdTag->getTagDataAs<uint32_t>()), 0x42524153, u32);

	pcpp::PPPoEDiscoveryLayer::PPPoETag* fourthTag = pppoeDiscoveryLayer->getTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE);
	PTF_ASSERT_NOT_NULL(fourthTag);
	PTF_ASSERT_TRUE(fourthTag == pppoeDiscoveryLayer->getNextTag(thirdTag));
	PTF_ASSERT_EQUAL(fourthTag->getType(), pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE, enum);
	PTF_ASSERT_EQUAL(fourthTag->tagDataLength, htobe16(16), u16);
	PTF_ASSERT_EQUAL(fourthTag->getTagDataAs<uint64_t>(), 0xf284240687050f3dULL, u64);
	PTF_ASSERT_EQUAL(fourthTag->getTagDataAs<uint64_t>(8), 0x5bbd77fdddb932dfULL, u64);
	PTF_ASSERT_NULL(pppoeDiscoveryLayer->getNextTag(fourthTag));

	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->getTagCount(), 4, int);

	PTF_ASSERT_EQUAL(pppoeDiscoveryLayer->toString(), std::string("PPP-over-Ethernet Discovery (PADS)"), string);
} // PPPoEDiscoveryLayerParsingTest



PTF_TEST_CASE(PPPoEDiscoveryLayerCreateTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/PPPoEDiscovery1.dat");

	pcpp::Packet samplePacket(&rawPacket1);

	pcpp::Packet pppoedPacket(1);

	pcpp::EthLayer ethLayer(*samplePacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(pppoedPacket.addLayer(&ethLayer));

	pcpp::PPPoEDiscoveryLayer pppoedLayer(1, 1, pcpp::PPPoELayer::PPPOE_CODE_PADI, 0);

	PTF_ASSERT_TRUE(pppoedPacket.addLayer(&pppoedLayer));

	pcpp::PPPoEDiscoveryLayer::PPPoETag* svcNamePtr = pppoedLayer.addTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_SVC_NAME, 0, NULL);

	uint32_t hostUniqData = htobe32(0x64138518);
	pppoedLayer.addTagAfter(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ, sizeof(uint32_t), (uint8_t*)(&hostUniqData), svcNamePtr);

	pppoedPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(pppoedPacket.getRawPacket()->getRawDataLen(), bufferLength1, int);
	PTF_ASSERT_BUF_COMPARE(pppoedPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	READ_FILE_INTO_BUFFER(2, "PacketExamples/PPPoEDiscovery2.dat");

	pcpp::EthLayer* ethLayerPtr = pppoedPacket.getLayerOfType<pcpp::EthLayer>();
	PTF_ASSERT_NOT_NULL(ethLayerPtr);
	ethLayerPtr->setSourceMac(pcpp::MacAddress("ca:01:0e:88:00:06"));
	ethLayerPtr->setDestMac(pcpp::MacAddress("cc:05:0e:88:00:00"));

	pppoedLayer.getPPPoEHeader()->code = pcpp::PPPoELayer::PPPOE_CODE_PADS;
	pppoedLayer.getPPPoEHeader()->sessionId = htobe16(0x11);

	pcpp::PPPoEDiscoveryLayer::PPPoETag* acCookieTag = pppoedLayer.addTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_COOKIE, 16, NULL);
	acCookieTag->setTagData<uint64_t>(0xf284240687050f3dULL);
	acCookieTag->setTagData<uint64_t>(0x5bbd77fdddb932dfULL, 8);

	pppoedLayer.addTagAfter(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HURL, sizeof(uint32_t), (uint8_t*)(&hostUniqData), acCookieTag);

	pcpp::PPPoEDiscoveryLayer::PPPoETag* hostUniqTag = pppoedLayer.getTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HOST_UNIQ);
	PTF_ASSERT_NOT_NULL(hostUniqTag);
	pcpp::PPPoEDiscoveryLayer::PPPoETag* acNameTag = pppoedLayer.addTagAfter(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, 4, NULL, hostUniqTag);
	acNameTag->setTagData<uint32_t>(htobe32(0x42524153));

	pcpp::LoggerPP::getInstance().suppressErrors();
	PTF_ASSERT_FALSE(pppoedLayer.removeTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_CREDITS));
	pcpp::LoggerPP::getInstance().enableErrors();

	PTF_ASSERT_TRUE(pppoedLayer.removeTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HURL));
	PTF_ASSERT_NULL(pppoedLayer.getTag(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_HURL));

	pppoedPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(pppoedPacket.getRawPacket()->getRawDataLen(), bufferLength2, int);
	PTF_ASSERT_BUF_COMPARE(pppoedPacket.getRawPacket()->getRawData(), buffer2, bufferLength2);

	delete [] buffer2;

	PTF_ASSERT_TRUE(pppoedLayer.removeAllTags());
	pppoedPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(pppoedLayer.getHeaderLen(), sizeof(pcpp::pppoe_header), size);
	PTF_ASSERT_EQUAL(pppoedLayer.getPPPoEHeader()->payloadLength, 0, u16);
} // PPPoEDiscoveryLayerCreateTest
