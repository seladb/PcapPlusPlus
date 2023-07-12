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

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/cotp.dat");

	pcpp::Packet CotpLayerTest(&cotpPacket);
	PTF_ASSERT_TRUE(CotpLayerTest.isPacketOfType(pcpp::COTP));
	auto cotpLayer = CotpLayerTest.getLayerOfType<pcpp::CotpLayer>();
	PTF_ASSERT_NOT_NULL(cotpLayer);
	PTF_ASSERT_EQUAL(cotpLayer->getHeaderLen(), 0x02);
	PTF_ASSERT_EQUAL(cotpLayer->getLength(), 0x02);
	PTF_ASSERT_EQUAL(cotpLayer->getPduType(), 0xf0);
	PTF_ASSERT_EQUAL(cotpLayer->getTpduNumber(), 0x80);
	PTF_ASSERT_EQUAL(cotpLayer->toString(), "Cotp Layer");

	pcpp::CotpLayer newCotpLayer(120);
	PTF_ASSERT_EQUAL(newCotpLayer.getLength(), 0x02);
	PTF_ASSERT_EQUAL(newCotpLayer.getPduType(), 0x0f);
	PTF_ASSERT_EQUAL(newCotpLayer.getTpduNumber(), 0x78);

	newCotpLayer.setLength((uint8_t)4);
	newCotpLayer.setPduType((uint8_t)210);
	newCotpLayer.setTpduNumber((uint8_t)125);
	PTF_ASSERT_EQUAL(newCotpLayer.getLength(), 0x04);
	PTF_ASSERT_EQUAL(newCotpLayer.getPduType(), 0xd2);
	PTF_ASSERT_EQUAL(newCotpLayer.getTpduNumber(), 0x7d);

} // CotpLayerTest
