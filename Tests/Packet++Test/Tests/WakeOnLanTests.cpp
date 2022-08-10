#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "GeneralUtils.h"
#include "Logger.h"
#include "Packet.h"
#include "WakeOnLanLayer.h"

PTF_TEST_CASE(WakeOnLanParsingTests)
{

	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/WoL_ether.dat");

	pcpp::Packet wolPacket1(&rawPacket1);
	pcpp::WakeOnLanLayer *wolLayer1 = wolPacket1.getLayerOfType<pcpp::WakeOnLanLayer>();

	PTF_ASSERT_NOT_NULL(wolLayer1);

	PTF_ASSERT_NOT_NULL(wolLayer1->getWakeOnLanHeader());
	PTF_ASSERT_EQUAL(wolLayer1->getTargetAddr(), pcpp::MacAddress("00:0d:56:dc:9e:35"));
	PTF_ASSERT_EQUAL(wolLayer1->getPassword(), "192.168.1.1");
	PTF_ASSERT_EQUAL(wolLayer1->toString(), "Wake On LAN 00:0d:56:dc:9e:35");

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/WoL_udp.dat");

	pcpp::Packet wolPacket2(&rawPacket2);
	pcpp::WakeOnLanLayer *wolLayer2 = wolPacket2.getLayerOfType<pcpp::WakeOnLanLayer>();

	PTF_ASSERT_NOT_NULL(wolLayer2);

	PTF_ASSERT_NOT_NULL(wolLayer2->getWakeOnLanHeader());
	PTF_ASSERT_EQUAL(wolLayer2->getTargetAddr(), pcpp::MacAddress("00:90:27:85:cf:01"));
	PTF_ASSERT_EQUAL(wolLayer2->getPassword(), "");
	PTF_ASSERT_EQUAL(wolLayer2->toString(), "Wake On LAN 00:90:27:85:cf:01");

}

PTF_TEST_CASE(WakeOnLanCreationTests)
{

	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/WoL_ether.dat");
	pcpp::Packet wolPacket1(&rawPacket1);
	pcpp::WakeOnLanLayer *wolLayer1 = wolPacket1.getLayerOfType<pcpp::WakeOnLanLayer>();
	PTF_ASSERT_NOT_NULL(wolLayer1);

	pcpp::WakeOnLanLayer wolcraftedLayer1(pcpp::MacAddress("00:0d:56:dc:9e:35"));
	PTF_ASSERT_TRUE(wolcraftedLayer1.setPassword(pcpp::IPv4Address("192.168.1.1")));
	
	PTF_ASSERT_EQUAL(wolcraftedLayer1.getDataLen(), wolLayer1->getDataLen());
	PTF_ASSERT_BUF_COMPARE(wolcraftedLayer1.getDataPtr(), wolLayer1->getDataPtr(), wolLayer1->getDataLen());

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/WoL_udp.dat");
	pcpp::Packet wolPacket2(&rawPacket2);
	pcpp::WakeOnLanLayer *wolLayer2 = wolPacket2.getLayerOfType<pcpp::WakeOnLanLayer>();
	PTF_ASSERT_NOT_NULL(wolLayer2);

	pcpp::WakeOnLanLayer wolcraftedLayer2(pcpp::MacAddress("00:90:27:85:cf:01"));

	PTF_ASSERT_EQUAL(wolcraftedLayer2.getDataLen(), wolLayer2->getDataLen());
	PTF_ASSERT_BUF_COMPARE(wolcraftedLayer2.getDataPtr(), wolLayer2->getDataPtr(), wolLayer2->getDataLen());

}

PTF_TEST_CASE(WakeOnLanEditTests)
{

	timeval time;
	gettimeofday(&time, NULL);
}
