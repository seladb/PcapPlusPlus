#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "CotpLayer.h"


using namespace std;

PTF_TEST_CASE(CotpLayerTest) {
    timeval time;
    gettimeofday(&time, nullptr);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/cotp.dat");

    pcpp::Packet CotpLayerTest(&rawPacket1);
    PTF_ASSERT_TRUE(CotpLayerTest.isPacketOfType(pcpp::COTP));
    auto cotpLayer = CotpLayerTest.getLayerOfType<pcpp::CotpLayer>();
    PTF_ASSERT_NOT_NULL(cotpLayer);
    PTF_ASSERT_EQUAL(cotpLayer->getLength(), 0x02);
    PTF_ASSERT_EQUAL(cotpLayer->getPdu_type(), 0xf0);
    PTF_ASSERT_EQUAL(cotpLayer->getTpdu_number(), 0x80);
	PTF_ASSERT_EQUAL(cotpLayer->toString(), "Cotp Layer length: 2, pdu_type: 240, tpdu_number: 128");

	pcpp::CotpLayer cotpLayerTest((uint8_t)3, (uint8_t)200, (uint8_t)120);
	PTF_ASSERT_EQUAL(cotpLayerTest.getLength(), 0x03);
	PTF_ASSERT_EQUAL(cotpLayerTest.getPdu_type(), 0xc8);
	PTF_ASSERT_EQUAL(cotpLayerTest.getTpdu_number(), 0x78);
	PTF_ASSERT_EQUAL(cotpLayerTest.toString(), "Cotp Layer length: 3, pdu_type: 200, tpdu_number: 120");

	cotpLayerTest.setLength((uint8_t)4);
	cotpLayerTest.setPdu_type((uint8_t)210);
	cotpLayerTest.setTpdu_number((uint8_t)125);
	PTF_ASSERT_EQUAL(cotpLayerTest.getLength(), 0x04);
	PTF_ASSERT_EQUAL(cotpLayerTest.getPdu_type(), 0xd2);
	PTF_ASSERT_EQUAL(cotpLayerTest.getTpdu_number(), 0x7d);
	PTF_ASSERT_EQUAL(cotpLayerTest.toString(), "Cotp Layer length: 4, pdu_type: 210, tpdu_number: 125");


} // CotpLayerTest
