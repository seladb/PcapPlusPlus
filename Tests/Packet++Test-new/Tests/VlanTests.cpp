#include "../Utils/TestUtils.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "ArpLayer.h"
#include "VlanLayer.h"
#include "../TestDefinition.h"

PTF_TEST_CASE(VlanParseAndCreation)
{
	for(int vid = 0; vid < 4096 * 2; vid++)
	{
		for(int prio = 0; prio < 8 * 2; prio ++)
		{
			for(int cfi = 0; cfi < 2 * 2; cfi++) //true or false
			{
				pcpp::VlanLayer testVlanLayer(vid, cfi, prio, PCPP_ETHERTYPE_VLAN);
				PTF_ASSERT(testVlanLayer.getVlanID() == (vid & 0xFFF), "vlan VID %d != %d; (c %d p %d)(%04X)", testVlanLayer.getVlanID(), vid, cfi, prio, testVlanLayer.getVlanHeader()->vlan);
				PTF_ASSERT(testVlanLayer.getPriority() == (prio & 7), "vlan PRIO %d != %d; (v %d c %d)(%04X)", testVlanLayer.getPriority(), prio, vid, cfi, testVlanLayer.getVlanHeader()->vlan);
				PTF_ASSERT(testVlanLayer.getCFI() == (cfi != 0), "vlan CFI %d != %d; (v %d p %d)(%04X)", testVlanLayer.getCFI(), cfi, vid, prio, testVlanLayer.getVlanHeader()->vlan);
			}
		}
	}

	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ArpRequestWithVlan.dat");

	pcpp::Packet arpWithVlan(&rawPacket1);

	pcpp::VlanLayer* firstVlanLayerPtr = arpWithVlan.getLayerOfType<pcpp::VlanLayer>();
	PTF_ASSERT_NOT_NULL(firstVlanLayerPtr);
  pcpp::VlanLayer* secondVlanLayerPtr = arpWithVlan.getNextLayerOfType<pcpp::VlanLayer>(firstVlanLayerPtr);
	PTF_ASSERT_EQUAL(firstVlanLayerPtr->getVlanID(), 666, u16);
	PTF_ASSERT_EQUAL(firstVlanLayerPtr->getCFI(), 1, u8);
	PTF_ASSERT_EQUAL(firstVlanLayerPtr->getPriority(), 5, u8);
	PTF_ASSERT_NOT_NULL(secondVlanLayerPtr);
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getVlanID(), 200, u16);
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getCFI(), 0, u8);
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getPriority(), 2, u8);

	pcpp::Packet arpWithVlanNew(1);
	pcpp::MacAddress macSrc("ca:03:0d:b4:00:1c");
	pcpp::MacAddress macDest("ff:ff:ff:ff:ff:ff");
	pcpp::EthLayer ethLayer(macSrc, macDest, PCPP_ETHERTYPE_VLAN);
	pcpp::VlanLayer firstVlanLayer(666, 1, 5, PCPP_ETHERTYPE_VLAN);
	pcpp::VlanLayer secondVlanLayer(200, 0, 2, PCPP_ETHERTYPE_ARP);
	pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, macSrc, pcpp::MacAddress("00:00:00:00:00:00"), pcpp::IPv4Address(std::string("192.168.2.200")), pcpp::IPv4Address(std::string("192.168.2.254")));
	PTF_ASSERT(arpWithVlanNew.addLayer(&ethLayer), "Couldn't add eth layer");
	PTF_ASSERT(arpWithVlanNew.addLayer(&firstVlanLayer), "Couldn't add first vlan layer");
	PTF_ASSERT(arpWithVlanNew.addLayer(&secondVlanLayer), "Couldn't add second vlan layer");
	PTF_ASSERT(arpWithVlanNew.addLayer(&arpLayer), "Couldn't add second arp layer");

	arpWithVlanNew.computeCalculateFields();

	PTF_ASSERT(bufferLength1 == arpWithVlanNew.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", arpWithVlanNew.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT(memcmp(arpWithVlanNew.getRawPacket()->getRawData(), buffer1, bufferLength1) == 0, "Raw packet data is different than expected");
} // VlanParseAndCreation