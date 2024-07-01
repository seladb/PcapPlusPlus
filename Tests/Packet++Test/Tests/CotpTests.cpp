#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "CotpLayer.h"
#include "Packet.h"
#include "SystemUtils.h"

using namespace std;

PTF_TEST_CASE(CotpLayerTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/tpkt_cotp.dat");

	pcpp::Packet cotpPacket(&rawPacket1);
	PTF_ASSERT_TRUE(cotpPacket.isPacketOfType(pcpp::COTP));
	auto cotpLayer = cotpPacket.getLayerOfType<pcpp::CotpLayer>();
	PTF_ASSERT_NOT_NULL(cotpLayer);
	PTF_ASSERT_EQUAL(cotpLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);
	PTF_ASSERT_EQUAL(cotpLayer->getHeaderLen(), 3);
	PTF_ASSERT_EQUAL(cotpLayer->getLength(), 0x02);
	PTF_ASSERT_EQUAL(cotpLayer->getPduType(), 0xf0);
	PTF_ASSERT_EQUAL(cotpLayer->getTpduNumber(), 0x80);
	PTF_ASSERT_EQUAL(cotpLayer->toString(), "Cotp Layer");

	pcpp::CotpLayer newCotpPacket(120);
	PTF_ASSERT_EQUAL(newCotpPacket.getHeaderLen(), 3);
	PTF_ASSERT_EQUAL(newCotpPacket.getLength(), 0x02);
	PTF_ASSERT_EQUAL(newCotpPacket.getPduType(), 0x0f);
	PTF_ASSERT_EQUAL(newCotpPacket.getTpduNumber(), 0x78);

	newCotpPacket.setLength((uint8_t)4);
	newCotpPacket.setPduType((uint8_t)210);
	newCotpPacket.setTpduNumber((uint8_t)125);
	PTF_ASSERT_EQUAL(newCotpPacket.getLength(), 0x04);
	PTF_ASSERT_EQUAL(newCotpPacket.getPduType(), 0xd2);
	PTF_ASSERT_EQUAL(newCotpPacket.getTpduNumber(), 0x7d);

}  // CotpLayerTest
