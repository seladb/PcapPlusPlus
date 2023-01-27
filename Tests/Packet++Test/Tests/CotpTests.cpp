#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "CotpLayer.h"

using namespace std;

PTF_TEST_CASE(CotpPacketNoOptionsParsing) {
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/cotp.dat");

	pcpp::Packet CotpPacketNoOptions(&rawPacket1);
	PTF_ASSERT_TRUE(CotpPacketNoOptions.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(CotpPacketNoOptions.isPacketOfType(pcpp::COTP));
	auto *cotpLayer = CotpPacketNoOptions.getLayerOfType<pcpp::CotpLayer>();
	PTF_ASSERT_NOT_NULL(cotpLayer);
	PTF_ASSERT_EQUAL(cotpLayer->getCotpHeader()->length, 0x02);
	PTF_ASSERT_EQUAL(cotpLayer->getCotpHeader()->pdu_type, 0xf0);
	PTF_ASSERT_EQUAL(cotpLayer->getCotpHeader()->tpdu_number, 0x80);

	PTF_ASSERT_EQUAL(cotpLayer->getCotpHeader()->length, cotpLayer->getLength());
	PTF_ASSERT_EQUAL(cotpLayer->getCotpHeader()->pdu_type, cotpLayer->getPdu_type());
	PTF_ASSERT_EQUAL(cotpLayer->getCotpHeader()->tpdu_number, cotpLayer->getTpdu_number());

} // CotpPacketNoOptionsParsing
