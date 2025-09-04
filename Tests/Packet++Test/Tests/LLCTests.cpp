#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "LLCLayer.h"

#include <cstring>

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(LLCParsingTests)
{
	auto rawPacket1 = createPacketFromHexResource("PacketExamples/StpConf.dat");

	pcpp::Packet llcPacket1(rawPacket1.get());
	PTF_ASSERT_TRUE(llcPacket1.isPacketOfType(pcpp::LLC));

	pcpp::LLCLayer* llcLayer1 = llcPacket1.getLayerOfType<pcpp::LLCLayer>();
	PTF_ASSERT_NOT_NULL(llcLayer1);

	pcpp::llc_header* header1 = llcLayer1->getLlcHeader();
	PTF_ASSERT_EQUAL(header1->dsap, 0x42);
	PTF_ASSERT_EQUAL(header1->ssap, 0x42);
	PTF_ASSERT_EQUAL(header1->control, 0x3);

	PTF_ASSERT_NOT_NULL(llcLayer1->getNextLayer());
	PTF_ASSERT_EQUAL(llcLayer1->getNextLayer()->getProtocol(), pcpp::STP, enum);

	PTF_ASSERT_EQUAL(llcLayer1->toString(), "Logical Link Control");

	auto rawPacket2 = createPacketFromHexResource("PacketExamples/llc_vlan.dat");
	pcpp::Packet llcPacket2(rawPacket2.get());
	pcpp::LLCLayer* llcLayer2 = llcPacket2.getLayerOfType<pcpp::LLCLayer>();

	PTF_ASSERT_NOT_NULL(llcLayer2);

	pcpp::llc_header* header2 = llcLayer2->getLlcHeader();
	PTF_ASSERT_EQUAL(header2->dsap, 0xaa);
	PTF_ASSERT_EQUAL(header2->ssap, 0xaa);
	PTF_ASSERT_EQUAL(header2->control, 0x3);
}  // LLCParsingTests

PTF_TEST_CASE(LLCCreationTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	auto rawPacket1 = createPacketFromHexResource("PacketExamples/StpConf.dat");

	pcpp::Packet llcPacket1(rawPacket1.get());
	PTF_ASSERT_TRUE(llcPacket1.isPacketOfType(pcpp::LLC));

	pcpp::LLCLayer* llcLayer1 = llcPacket1.getLayerOfType<pcpp::LLCLayer>();
	PTF_ASSERT_NOT_NULL(llcLayer1);

	pcpp::LLCLayer craftedLayer1(0x42, 0x42, 0x3);
	PTF_ASSERT_BUF_COMPARE(llcLayer1->getData(), craftedLayer1.getData(), craftedLayer1.getDataLen());
}  // LLCCreationTests
