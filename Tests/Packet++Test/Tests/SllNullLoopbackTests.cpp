#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "MacAddress.h"
#include "Packet.h"
#include "SllLayer.h"
#include "NullLoopbackLayer.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "TcpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(SllPacketParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/SllPacket.dat", pcpp::LINKTYPE_LINUX_SLL);

	pcpp::Packet sllPacket(&rawPacket1);

	PTF_ASSERT_TRUE(sllPacket.isPacketOfType(pcpp::SLL));
	PTF_ASSERT_EQUAL(sllPacket.getFirstLayer()->getProtocol(), pcpp::SLL, enum);
	pcpp::SllLayer* sllLayer = sllPacket.getLayerOfType<pcpp::SllLayer>();
	PTF_ASSERT_NOT_NULL(sllLayer->getNextLayer());
	PTF_ASSERT_EQUAL(sllLayer->getNextLayer()->getProtocol(), pcpp::IPv6, enum);
	PTF_ASSERT_TRUE(sllPacket.isPacketOfType(pcpp::HTTP));
	PTF_ASSERT_NOT_NULL(sllLayer);
	PTF_ASSERT_EQUAL(sllLayer, sllPacket.getFirstLayer(), ptr);
	PTF_ASSERT_EQUAL(sllLayer->getSllHeader()->packet_type, 0);
	PTF_ASSERT_EQUAL(sllLayer->getSllHeader()->ARPHRD_type, htobe16(1));
	PTF_ASSERT_EQUAL(sllLayer->getSllHeader()->link_layer_addr_len, htobe16(6));
	pcpp::MacAddress macAddrFromPacket(sllLayer->getSllHeader()->link_layer_addr);
	pcpp::MacAddress macAddrRef("00:12:44:1e:74:00");
	PTF_ASSERT_EQUAL(macAddrRef, macAddrFromPacket);
	PTF_ASSERT_EQUAL(sllLayer->getSllHeader()->protocol_type, htobe16(PCPP_ETHERTYPE_IPV6));
}  // SllPacketParsingTest

PTF_TEST_CASE(SllPacketCreationTest)
{
	pcpp::SllLayer sllLayer(4, 1);
	sllLayer.setMacAddressAsLinkLayer(pcpp::MacAddress("00:30:48:dd:00:53"));
	sllLayer.getSllHeader()->link_layer_addr[6] = 0xf6;
	sllLayer.getSllHeader()->link_layer_addr[7] = 0x7f;

	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address(std::string("130.217.250.13")), pcpp::IPv4Address("130.217.250.128"));
	ipLayer.getIPv4Header()->fragmentOffset = 0x40;
	ipLayer.getIPv4Header()->ipId = htobe16(63242);
	ipLayer.getIPv4Header()->timeToLive = 64;

	pcpp::TcpLayer tcpLayer((uint16_t)55013, (uint16_t)6000);
	tcpLayer.getTcpHeader()->sequenceNumber = htobe32(0x92f2ad86);
	tcpLayer.getTcpHeader()->ackNumber = htobe32(0x7633e977);
	tcpLayer.getTcpHeader()->ackFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htobe16(4098);
	PTF_ASSERT_TRUE(
	    tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NopEolOptionEnumType::Nop)).isNotNull());
	PTF_ASSERT_TRUE(
	    tcpLayer.addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NopEolOptionEnumType::Nop)).isNotNull());
	pcpp::TcpOption tsOption = tcpLayer.addTcpOption(
	    pcpp::TcpOptionBuilder(pcpp::TcpOptionEnumType::Timestamp, nullptr, PCPP_TCPOLEN_TIMESTAMP - 2));
	PTF_ASSERT_TRUE(tsOption.isNotNull());
	tsOption.setValue<uint32_t>(htobe32(0x0402383b));
	tsOption.setValue<uint32_t>(htobe32(0x03ff37f5), 4);

	pcpp::Packet sllPacket(1);
	PTF_ASSERT_TRUE(sllPacket.addLayer(&sllLayer));
	PTF_ASSERT_TRUE(sllPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(sllPacket.addLayer(&tcpLayer));

	sllPacket.computeCalculateFields();

	READ_FILE_INTO_BUFFER(1, "PacketExamples/SllPacket2.dat");

	PTF_ASSERT_EQUAL(sllPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(sllPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	delete[] buffer1;
}  // SllPacketCreationTest

PTF_TEST_CASE(NullLoopbackTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/NullLoopback1.dat", pcpp::LINKTYPE_NULL);
	READ_FILE_AND_CREATE_PACKET_LINKTYPE(2, "PacketExamples/NullLoopback2.dat", pcpp::LINKTYPE_NULL);
	READ_FILE_AND_CREATE_PACKET_LINKTYPE(3, "PacketExamples/NullLoopback3.dat", pcpp::LINKTYPE_NULL);

	pcpp::Packet nullPacket1(&rawPacket1);
	pcpp::Packet nullPacket2(&rawPacket2);
	pcpp::Packet nullPacket3(&rawPacket3);

	pcpp::NullLoopbackLayer* nullLoopbackLayer;
	pcpp::Layer* nextLayer;

	PTF_ASSERT_TRUE(nullPacket1.isPacketOfType(pcpp::NULL_LOOPBACK));
	nullLoopbackLayer = nullPacket1.getLayerOfType<pcpp::NullLoopbackLayer>();
	PTF_ASSERT_NOT_NULL(nullLoopbackLayer);
	nextLayer = nullLoopbackLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(nextLayer);
	PTF_ASSERT_EQUAL(nextLayer->getProtocol(), pcpp::IPv6, enum);
	PTF_ASSERT_EQUAL(nullLoopbackLayer->getFamily(), PCPP_BSD_AF_INET6_DARWIN);

	PTF_ASSERT_TRUE(nullPacket2.isPacketOfType(pcpp::NULL_LOOPBACK));
	nullLoopbackLayer = nullPacket2.getLayerOfType<pcpp::NullLoopbackLayer>();
	PTF_ASSERT_NOT_NULL(nullLoopbackLayer);
	nextLayer = nullLoopbackLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(nextLayer);
	PTF_ASSERT_EQUAL(nextLayer->getProtocol(), pcpp::IPv4, enum);
	PTF_ASSERT_EQUAL(((pcpp::IPv4Layer*)nextLayer)->getSrcIPAddress(), pcpp::IPv4Address("172.16.1.117"));
	PTF_ASSERT_EQUAL(nullLoopbackLayer->getFamily(), PCPP_BSD_AF_INET);

	PTF_ASSERT_TRUE(nullPacket3.isPacketOfType(pcpp::NULL_LOOPBACK));
	nullLoopbackLayer = nullPacket3.getLayerOfType<pcpp::NullLoopbackLayer>();
	PTF_ASSERT_NOT_NULL(nullLoopbackLayer);
	nextLayer = nullLoopbackLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(nextLayer);
	PTF_ASSERT_EQUAL(nextLayer->getProtocol(), pcpp::IPv4, enum);
	PTF_ASSERT_GREATER_THAN(nullLoopbackLayer->getFamily(), 1500);

	pcpp::NullLoopbackLayer newNullLoopbackLayer(PCPP_BSD_AF_INET);
	pcpp::IPv4Layer newIp4Layer(pcpp::IPv4Address("172.16.1.117"), pcpp::IPv4Address("172.16.1.255"));
	newIp4Layer.getIPv4Header()->ipId = htobe16(49513);
	newIp4Layer.getIPv4Header()->timeToLive = 64;

	pcpp::UdpLayer newUdpLayer(55369, 8612);

	uint8_t payload[] = {
		0x42, 0x4a, 0x4e, 0x42, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	pcpp::PayloadLayer newPayloadLayer(payload, 16);

	pcpp::Packet newNullPacket(1);
	PTF_ASSERT_TRUE(newNullPacket.addLayer(&newNullLoopbackLayer));
	PTF_ASSERT_TRUE(newNullPacket.addLayer(&newIp4Layer));
	PTF_ASSERT_TRUE(newNullPacket.addLayer(&newUdpLayer));
	PTF_ASSERT_TRUE(newNullPacket.addLayer(&newPayloadLayer));

	newNullPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(newNullPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(newNullPacket.getRawPacket()->getRawData(), buffer2, bufferLength2);
}  // NullLoopbackTest
