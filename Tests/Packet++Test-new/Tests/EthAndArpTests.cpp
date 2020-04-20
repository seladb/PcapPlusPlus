#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "MacAddress.h"
#include "IpAddress.h"
#include "EthLayer.h"
#include "ArpLayer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include "../TestDefinition.h"
#include "SystemUtils.h"

PTF_TEST_CASE(EthPacketCreation)
{
	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04 };
	pcpp::PayloadLayer payloadLayer(payload, 4, true);

	pcpp::Packet ethPacket(1);
	PTF_ASSERT_TRUE(ethPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(ethPacket.addLayer(&payloadLayer));

	PTF_ASSERT_TRUE(ethPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NOT_NULL(ethPacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT(ethPacket.getLayerOfType<pcpp::EthLayer>() == &ethLayer, "Ethernet layer doesn't equal to inserted layer");
	PTF_ASSERT_EQUAL(ethPacket.getLayerOfType<pcpp::EthLayer>()->getDestMac(), dstMac, object);
	PTF_ASSERT_EQUAL(ethPacket.getLayerOfType<pcpp::EthLayer>()->getSourceMac(), srcMac, object);
	PTF_ASSERT_EQUAL(ethPacket.getLayerOfType<pcpp::EthLayer>()->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_IP), u16);

	pcpp::RawPacket* rawPacket = ethPacket.getRawPacket();
	PTF_ASSERT_NOT_NULL(rawPacket);
	PTF_ASSERT_EQUAL(rawPacket->getRawDataLen(), 18, int);

	uint8_t expectedBuffer[18] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04 };
	PTF_ASSERT_BUF_COMPARE(rawPacket->getRawData(), expectedBuffer, 18);
} // EthPacketCreation

PTF_TEST_CASE(EthPacketPointerCreation)
{
	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer* ethLayer = new pcpp::EthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04 };
	pcpp::PayloadLayer* payloadLayer = new pcpp::PayloadLayer(payload, 4, true);

	pcpp::Packet* ethPacket = new pcpp::Packet(1);
	PTF_ASSERT_TRUE(ethPacket->addLayer(ethLayer, true));
	PTF_ASSERT_TRUE(ethPacket->addLayer(payloadLayer, true));

	PTF_ASSERT_TRUE(ethPacket->isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NOT_NULL(ethPacket->getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT(ethPacket->getLayerOfType<pcpp::EthLayer>() == ethLayer, "Ethernet layer doesn't equal to inserted layer");
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>()->getDestMac(), dstMac, object);
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>()->getSourceMac(), srcMac, object);
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>()->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_IP), u16);

	pcpp::RawPacket* rawPacket = ethPacket->getRawPacket();
	PTF_ASSERT_NOT_NULL(rawPacket);
	PTF_ASSERT_EQUAL(rawPacket->getRawDataLen(), 18, int);

	uint8_t expectedBuffer[18] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04 };
	PTF_ASSERT_BUF_COMPARE(rawPacket->getRawData(), expectedBuffer, 18);
	delete(ethPacket);
} // EthPacketPointerCreation



PTF_TEST_CASE(EthAndArpPacketParsing)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ArpResponsePacket.dat");

	pcpp::Packet ethPacket(&rawPacket1);
	PTF_ASSERT(ethPacket.isPacketOfType(pcpp::Ethernet), "Packet is not of type Ethernet");
	PTF_ASSERT(ethPacket.getLayerOfType<pcpp::EthLayer>() != NULL, "Ethernet layer doesn't exist");

	pcpp::MacAddress expectedSrcMac(0x30, 0x46, 0x9a, 0x23, 0xfb, 0xfa);
	pcpp::MacAddress expectedDstMac(0x6c, 0xf0, 0x49, 0xb2, 0xde, 0x6e);
	pcpp::EthLayer* ethLayer = ethPacket.getLayerOfType<pcpp::EthLayer>();
	PTF_ASSERT_EQUAL(ethLayer->getDestMac(), expectedDstMac, object);
	PTF_ASSERT_EQUAL(ethLayer->getSourceMac(), expectedSrcMac, object);
	PTF_ASSERT_EQUAL(ethLayer->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_ARP), hex);

	PTF_ASSERT_EQUAL(ethLayer->getNextLayer()->getProtocol(), pcpp::ARP, enum);
	pcpp::ArpLayer* arpLayer = (pcpp::ArpLayer*)ethLayer->getNextLayer();
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->hardwareType, htobe16(1), u16);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->protocolType, htobe16(PCPP_ETHERTYPE_IP), hex);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->hardwareSize, 6, u8);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->protocolSize, 4, u8);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->opcode, htobe16(pcpp::ARP_REPLY), u16);
	PTF_ASSERT_EQUAL(arpLayer->getSenderIpAddr(), pcpp::IPv4Address(std::string("10.0.0.138")), object);
	PTF_ASSERT_EQUAL(arpLayer->getTargetMacAddress(), pcpp::MacAddress("6c:f0:49:b2:de:6e"), object);
} // EthAndArpPacketParsing

PTF_TEST_CASE(ArpPacketCreation)
{
	pcpp::MacAddress srcMac("6c:f0:49:b2:de:6e");
	pcpp::MacAddress dstMac("ff:ff:ff:ff:ff:ff:");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_ARP);

	pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, srcMac, srcMac, pcpp::IPv4Address(std::string("10.0.0.1")), pcpp::IPv4Address(std::string("10.0.0.138")));

	pcpp::Packet arpRequestPacket(1);
	PTF_ASSERT_TRUE(arpRequestPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(arpRequestPacket.addLayer(&arpLayer));
	arpRequestPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(arpRequestPacket.getRawPacket()->getRawDataLen(), 42, int);

	pcpp::ArpLayer* pArpLayer = arpRequestPacket.getLayerOfType<pcpp::ArpLayer>();
	PTF_ASSERT_NOT_NULL(pArpLayer);

	pcpp::arphdr* arpHeader = pArpLayer->getArpHeader();
	PTF_ASSERT_EQUAL(arpHeader->hardwareSize, 6, u8);
	PTF_ASSERT_EQUAL(arpHeader->protocolType, htobe16(PCPP_ETHERTYPE_IP), u16);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/ArpRequestPacket.dat");

	PTF_ASSERT_EQUAL(bufferLength1, arpRequestPacket.getRawPacket()->getRawDataLen(), int);
	PTF_ASSERT_BUF_COMPARE(arpRequestPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	delete [] buffer1;
} // ArpPacketCreation
