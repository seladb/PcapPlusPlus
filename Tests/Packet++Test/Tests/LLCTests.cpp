#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "LLCLayer.h"

PTF_TEST_CASE(LLCParsingTests)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/StpConf.dat");

	pcpp::Packet stpPacket(&rawPacket1);
	pcpp::LLCLayer *llcLayer = stpPacket.getLayerOfType<pcpp::LLCLayer>();

	PTF_ASSERT_NOT_NULL(llcLayer);

	pcpp::llc_header *header = llcLayer->getLlcHeader();
	PTF_ASSERT_EQUAL(header->dsap, 0x42);
	PTF_ASSERT_EQUAL(header->ssap, 0x42);
	PTF_ASSERT_EQUAL(header->control, 0x3);

	PTF_ASSERT_NOT_NULL(llcLayer->getNextLayer());
	PTF_ASSERT_EQUAL(llcLayer->getNextLayer()->getProtocol(), pcpp::STP, enum);

	PTF_ASSERT_EQUAL(llcLayer->toString(), "Logical Link Control");

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/llc_vlan.dat");
	pcpp::Packet llcPacket(&rawPacket2);
	pcpp::LLCLayer *llcLayer2 = llcPacket.getLayerOfType<pcpp::LLCLayer>();

	PTF_ASSERT_NOT_NULL(llcLayer2);

	pcpp::llc_header *header2 = llcLayer2->getLlcHeader();
	PTF_ASSERT_EQUAL(header2->dsap, 0xaa);
	PTF_ASSERT_EQUAL(header2->ssap, 0xaa);
	PTF_ASSERT_EQUAL(header2->control, 0x3);

}
