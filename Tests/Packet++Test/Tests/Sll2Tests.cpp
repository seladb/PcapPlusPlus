#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "MacAddress.h"
#include "Packet.h"
#include "Sll2Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

PTF_TEST_CASE(Sll2PacketParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET_LINKTYPE(1, "PacketExamples/Sll2Packet.dat", pcpp::LINKTYPE_LINUX_SLL2);

	pcpp::Packet sll2Packet(&rawPacket1);

	PTF_ASSERT_TRUE(sll2Packet.isPacketOfType(pcpp::SLL2));
	PTF_ASSERT_EQUAL(sll2Packet.getFirstLayer()->getProtocol(), pcpp::SLL2, enum);
	pcpp::Sll2Layer* sll2Layer = sll2Packet.getLayerOfType<pcpp::Sll2Layer>();
	PTF_ASSERT_NOT_NULL(sll2Layer->getNextLayer());
	PTF_ASSERT_EQUAL(sll2Layer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	PTF_ASSERT_TRUE(sll2Packet.isPacketOfType(pcpp::SLL2));
	PTF_ASSERT_NOT_NULL(sll2Layer);
	PTF_ASSERT_EQUAL(sll2Layer, sll2Packet.getFirstLayer(), ptr);
	PTF_ASSERT_EQUAL(sll2Layer->getSll2Header()->protocol_type, htobe16(PCPP_ETHERTYPE_IP));
	PTF_ASSERT_EQUAL(sll2Layer->getSll2Header()->interface_index_type, htobe32(20));
	PTF_ASSERT_EQUAL(sll2Layer->getSll2Header()->ARPHRD_type, htobe16(1));
	PTF_ASSERT_EQUAL(sll2Layer->getSll2Header()->packet_type, 4);
	PTF_ASSERT_EQUAL(sll2Layer->getHeaderLen(), 20);
	PTF_ASSERT_EQUAL(sll2Layer->getSll2Header()->link_layer_addr_len, 6);
	pcpp::MacAddress macAddrFromPacket(sll2Layer->getSll2Header()->link_layer_addr);
	pcpp::MacAddress macAddrRef("d2:cf:c2:50:15:ea");
	PTF_ASSERT_EQUAL(macAddrRef, macAddrFromPacket);
} // Sll2PacketParsingTest

PTF_TEST_CASE(Sll2PacketCreationTest)
{
	pcpp::Sll2Layer sll2Layer(20, 1, 4);
	sll2Layer.setMacAddressAsLinkLayer(pcpp::MacAddress("d2:cf:c2:50:15:ea"));
	sll2Layer.getSll2Header()->link_layer_addr[6] = 0x00;
	sll2Layer.getSll2Header()->link_layer_addr[7] = 0x00;

	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address(std::string("7.249.151.114")),
							pcpp::IPv4Address("116.63.66.108"));
	ipLayer.getIPv4Header()->fragmentOffset = 0x40;
	ipLayer.getIPv4Header()->ipId = htobe16(35618);
	ipLayer.getIPv4Header()->timeToLive = 64;

	pcpp::TcpLayer tcpLayer((uint16_t)57292, (uint16_t)443);
	tcpLayer.getTcpHeader()->sequenceNumber = htobe32(0xa7ab9fbf);
	tcpLayer.getTcpHeader()->ackNumber = htobe32(0xaaceb5e9);
	tcpLayer.getTcpHeader()->ackFlag = 1;
	tcpLayer.getTcpHeader()->windowSize = htobe16(1058);

	pcpp::Packet sllPacket(1);
	PTF_ASSERT_TRUE(sllPacket.addLayer(&sll2Layer));
	PTF_ASSERT_TRUE(sllPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(sllPacket.addLayer(&tcpLayer));
	sllPacket.computeCalculateFields();

	READ_FILE_INTO_BUFFER(1, "PacketExamples/Sll2Packet.dat");
	PTF_ASSERT_EQUAL(sllPacket.getRawPacket()->getRawDataLen(), 60);
	PTF_ASSERT_BUF_COMPARE(sllPacket.getRawPacket()->getRawData(), buffer1, 52);

	delete [] buffer1;
} // Sll2PacketCreationTest