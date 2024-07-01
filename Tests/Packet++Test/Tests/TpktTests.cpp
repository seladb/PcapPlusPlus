#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "TpktLayer.h"
#include <iostream>

PTF_TEST_CASE(TpktLayerTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/tpkt_cotp.dat");

	pcpp::Packet TpktPacketNoOptions(&rawPacket1);
	PTF_ASSERT_TRUE(TpktPacketNoOptions.isPacketOfType(pcpp::TPKT));
	auto tpktLayer = TpktPacketNoOptions.getLayerOfType<pcpp::TpktLayer>();
	PTF_ASSERT_NOT_NULL(tpktLayer);

	PTF_ASSERT_EQUAL(tpktLayer->getVersion(), 3);
	PTF_ASSERT_EQUAL(tpktLayer->getReserved(), 0);
	PTF_ASSERT_EQUAL(tpktLayer->getLength(), 607);

	PTF_ASSERT_EQUAL(tpktLayer->toString(), "TPKT Layer, version: 3, length: 607");

	pcpp::TpktLayer tpktLayerTest((uint8_t)8, (uint16_t)605);
	PTF_ASSERT_EQUAL(tpktLayerTest.getVersion(), 8);
	PTF_ASSERT_EQUAL(tpktLayerTest.getLength(), 605);
	PTF_ASSERT_EQUAL(tpktLayerTest.toString(), "TPKT Layer, version: 8, length: 605");

	tpktLayerTest.setVersion((uint8_t)10);
	tpktLayerTest.setLength((uint16_t)602);
	PTF_ASSERT_EQUAL(tpktLayerTest.getVersion(), 10);
	PTF_ASSERT_EQUAL(tpktLayerTest.getLength(), 602);
	PTF_ASSERT_EQUAL(tpktLayerTest.toString(), "TPKT Layer, version: 10, length: 602");

}  // TpktLayerTest
