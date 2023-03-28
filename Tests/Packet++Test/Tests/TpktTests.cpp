#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "TpktLayer.h"
#include <iostream>

PTF_TEST_CASE(TpktPacketNoOptionsParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/tpkt.dat");

	pcpp::Packet TpktPacketNoOptions(&rawPacket1);
	PTF_ASSERT_TRUE(TpktPacketNoOptions.isPacketOfType(pcpp::TPKT));
	auto tpktLayer = TpktPacketNoOptions.getLayerOfType<pcpp::TpktLayer>();
	PTF_ASSERT_NOT_NULL(tpktLayer);

	PTF_ASSERT_EQUAL(tpktLayer->getTpktHeader()->version, 3);
	PTF_ASSERT_EQUAL(tpktLayer->getTpktHeader()->reserved, 0);
	PTF_ASSERT_EQUAL(tpktLayer->getTpktHeader()->length, htobe16(607));

} // TpktPacketNoOptionsParsing
