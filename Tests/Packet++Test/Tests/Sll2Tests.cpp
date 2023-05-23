#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "MacAddress.h"
#include "Packet.h"
#include "Sll2Layer.h"
#include "UdpLayer.h"
#include "EthLayer.h"

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
	PTF_ASSERT_EQUAL(sll2Layer->getSll2Header()->link_layer_addr_len, 6);
	pcpp::MacAddress macAddrFromPacket(sll2Layer->getSll2Header()->link_layer_addr);
	pcpp::MacAddress macAddrRef("d2:cf:c2:50:15:ea");
	PTF_ASSERT_EQUAL(macAddrRef, macAddrFromPacket);
} // Sll2PacketParsingTest