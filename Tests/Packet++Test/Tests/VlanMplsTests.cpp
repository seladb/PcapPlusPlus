#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "ArpLayer.h"
#include "VlanLayer.h"
#include "MplsLayer.h"
#include "VxlanLayer.h"
#include "PayloadLayer.h"
#include "UdpLayer.h"
#include "SystemUtils.h"

using pcpp_tests::utils::createPacketAndBufferFromHexResource;
using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(VlanParseAndCreation)
{
	for (int vid = 0; vid < 4096 * 2; vid++)
	{
		for (int prio = 0; prio < 8 * 2; prio++)
		{
			for (int cfi = 0; cfi < 2 * 2; cfi++)  // true or false
			{
				pcpp::VlanLayer testVlanLayer(vid, cfi, prio, PCPP_ETHERTYPE_VLAN);
				PTF_ASSERT_EQUAL(testVlanLayer.getVlanID(), (vid & 0xFFF));
				PTF_ASSERT_EQUAL(testVlanLayer.getPriority(), (prio & 7));
				PTF_ASSERT_EQUAL(testVlanLayer.getCFI(), (cfi != 0));
			}
		}
	}

	auto rawPacketAndBuf1 = createPacketAndBufferFromHexResource("PacketExamples/ArpRequestWithVlan.dat");
	auto& resource1 = rawPacketAndBuf1.resourceBuffer;
	auto& rawPacket1 = rawPacketAndBuf1.packet;

	pcpp::Packet arpWithVlan(rawPacket1.get());

	pcpp::VlanLayer* firstVlanLayerPtr = arpWithVlan.getLayerOfType<pcpp::VlanLayer>();
	PTF_ASSERT_NOT_NULL(firstVlanLayerPtr);
	pcpp::VlanLayer* secondVlanLayerPtr = arpWithVlan.getNextLayerOfType<pcpp::VlanLayer>(firstVlanLayerPtr);
	PTF_ASSERT_EQUAL(firstVlanLayerPtr->getVlanID(), 666);
	PTF_ASSERT_EQUAL(firstVlanLayerPtr->getCFI(), 1);
	PTF_ASSERT_EQUAL(firstVlanLayerPtr->getPriority(), 5);
	PTF_ASSERT_NOT_NULL(secondVlanLayerPtr);
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getVlanID(), 200);
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getCFI(), 0);
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getPriority(), 2);

	pcpp::MacAddress macSrc("ca:03:0d:b4:00:1c");
	pcpp::MacAddress macDest("ff:ff:ff:ff:ff:ff");
	// Don't set EtherType for EthLayer and the first VlanLayer,
	// they will be set automatically by computeCalculateFields()
	pcpp::EthLayer ethLayer(macSrc, macDest);
	pcpp::VlanLayer firstVlanLayer(666, 1, 5);
	pcpp::VlanLayer secondVlanLayer(200, 0, 2, PCPP_ETHERTYPE_ARP);
	pcpp::ArpLayer arpLayer(
	    pcpp::ArpRequest(macSrc, pcpp::IPv4Address("192.168.2.200"), pcpp::IPv4Address("192.168.2.254")));
	pcpp::Packet arpWithVlanNew(1);
	PTF_ASSERT_TRUE(arpWithVlanNew.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(arpWithVlanNew.addLayer(&firstVlanLayer));
	PTF_ASSERT_TRUE(arpWithVlanNew.addLayer(&secondVlanLayer));
	PTF_ASSERT_TRUE(arpWithVlanNew.addLayer(&arpLayer));

	arpWithVlanNew.computeCalculateFields();

	PTF_ASSERT_EQUAL(arpWithVlanNew.getRawPacket()->getRawDataLen(), resource1.length);
	PTF_ASSERT_BUF_COMPARE(arpWithVlanNew.getRawPacket()->getRawData(), resource1.data.get(), resource1.length);
}  // VlanParseAndCreation

PTF_TEST_CASE(QinQ802_1adParse)
{
	timeval time;
	gettimeofday(&time, nullptr);

	auto rawPacket1 = createPacketFromHexResource("PacketExamples/QinQ_802.1_AD.dat");
	pcpp::Packet qinq8021adPacket(rawPacket1.get());

	pcpp::VlanLayer* firstVlanLayerPtr = qinq8021adPacket.getLayerOfType<pcpp::VlanLayer>();
	PTF_ASSERT_NOT_NULL(firstVlanLayerPtr);
	pcpp::VlanLayer* secondVlanLayerPtr = qinq8021adPacket.getNextLayerOfType<pcpp::VlanLayer>(firstVlanLayerPtr);
	PTF_ASSERT_EQUAL(firstVlanLayerPtr->getVlanID(), 30);
	PTF_ASSERT_EQUAL(firstVlanLayerPtr->getCFI(), 0);
	PTF_ASSERT_EQUAL(firstVlanLayerPtr->getPriority(), 0);
	PTF_ASSERT_NOT_NULL(secondVlanLayerPtr);
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getVlanID(), 100);
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getCFI(), 0);
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getPriority(), 0);
	PTF_ASSERT_NOT_NULL(secondVlanLayerPtr->getNextLayer());
	PTF_ASSERT_EQUAL(secondVlanLayerPtr->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
}  // QinQ802_1adParse

PTF_TEST_CASE(MplsLayerTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	auto rawPacket1 = createPacketFromHexResource("PacketExamples/MplsPackets1.dat");
	auto rawPacket2 = createPacketFromHexResource("PacketExamples/MplsPackets2.dat");

	pcpp::Packet mplsPacket1(rawPacket1.get());
	pcpp::Packet mplsPacket2(rawPacket2.get());

	pcpp::MplsLayer* mplsLayer = mplsPacket1.getLayerOfType<pcpp::MplsLayer>();
	PTF_ASSERT_NOT_NULL(mplsLayer);

	PTF_ASSERT_EQUAL(mplsLayer->getTTL(), 126);
	PTF_ASSERT_TRUE(mplsLayer->isBottomOfStack());
	PTF_ASSERT_EQUAL(mplsLayer->getExperimentalUseValue(), 0);
	PTF_ASSERT_EQUAL(mplsLayer->getMplsLabel(), 16000);

	PTF_ASSERT_NOT_NULL(mplsLayer->getNextLayer());
	PTF_ASSERT_EQUAL(mplsLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);

	mplsLayer = mplsPacket2.getLayerOfType<pcpp::MplsLayer>();
	PTF_ASSERT_NOT_NULL(mplsLayer);

	PTF_ASSERT_EQUAL(mplsLayer->getTTL(), 254);
	PTF_ASSERT_FALSE(mplsLayer->isBottomOfStack());
	PTF_ASSERT_EQUAL(mplsLayer->getExperimentalUseValue(), 0);
	PTF_ASSERT_EQUAL(mplsLayer->getMplsLabel(), 18);

	mplsLayer = mplsPacket2.getNextLayerOfType<pcpp::MplsLayer>(mplsLayer);
	PTF_ASSERT_NOT_NULL(mplsLayer);

	PTF_ASSERT_EQUAL(mplsLayer->getTTL(), 255);
	PTF_ASSERT_TRUE(mplsLayer->isBottomOfStack());
	PTF_ASSERT_EQUAL(mplsLayer->getExperimentalUseValue(), 0);
	PTF_ASSERT_EQUAL(mplsLayer->getMplsLabel(), 16);

	PTF_ASSERT_NOT_NULL(mplsLayer->getNextLayer());
	PTF_ASSERT_EQUAL(mplsLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);

	mplsLayer->setBottomOfStack(true);
	PTF_ASSERT_TRUE(mplsLayer->setExperimentalUseValue(6));
	mplsLayer->setTTL(111);
	PTF_ASSERT_TRUE(mplsLayer->setMplsLabel(100000));
	uint8_t expectedResult[4] = { 0x18, 0x6A, 0x0d, 0x6f };
	PTF_ASSERT_BUF_COMPARE(mplsLayer->getData(), expectedResult, 4);
	PTF_ASSERT_EQUAL(mplsLayer->getTTL(), 111);
	PTF_ASSERT_EQUAL(mplsLayer->getMplsLabel(), 100000);
	PTF_ASSERT_EQUAL(mplsLayer->getExperimentalUseValue(), 6);
	PTF_ASSERT_TRUE(mplsLayer->isBottomOfStack());

	pcpp::MplsLayer mplsLayer2(0xdff0f, 20, 7, false);
	uint8_t expectedResult2[4] = { 0xdf, 0xf0, 0xfe, 0x14 };
	PTF_ASSERT_BUF_COMPARE(mplsLayer2.getData(), expectedResult2, 4);

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(mplsLayer->setMplsLabel(0xFFFFFF));
	pcpp::Logger::getInstance().enableLogs();

	// create a new packet with MPLS
	pcpp::EthLayer eth1(*mplsPacket2.getLayerOfType<pcpp::EthLayer>());
	pcpp::MplsLayer mpls1(5000, 254, 0, true);
	pcpp::MplsLayer mpls2(18, 254, 0, true);
	pcpp::EthLayer eth2(*mplsPacket2.getLayerOfType<pcpp::EthLayer>());
	pcpp::PayloadLayer payload("00000000");
	pcpp::Packet newMplsPacket;
	newMplsPacket.addLayer(&eth1);
	newMplsPacket.addLayer(&mpls1);
	newMplsPacket.addLayer(&mpls2);
	newMplsPacket.addLayer(&payload);
	newMplsPacket.addLayer(&eth2);
	newMplsPacket.computeCalculateFields();
	mplsLayer = newMplsPacket.getLayerOfType<pcpp::MplsLayer>();
	PTF_ASSERT_EQUAL(mplsLayer->getMplsLabel(), 5000);
	PTF_ASSERT_EQUAL(mplsLayer->getExperimentalUseValue(), 0);
	PTF_ASSERT_FALSE(mplsLayer->isBottomOfStack());
	mplsLayer = newMplsPacket.getNextLayerOfType<pcpp::MplsLayer>(mplsLayer);
	PTF_ASSERT_EQUAL(mplsLayer->getMplsLabel(), 18);
	PTF_ASSERT_EQUAL(mplsLayer->getExperimentalUseValue(), 0);
	PTF_ASSERT_TRUE(mplsLayer->isBottomOfStack());
}  // MplsLayerTest

PTF_TEST_CASE(VxlanParsingAndCreationTest)
{
	auto rawPacketAndBuf1 = createPacketAndBufferFromHexResource("PacketExamples/Vxlan1.dat");
	auto& resource1 = rawPacketAndBuf1.resourceBuffer;
	auto& rawPacket1 = rawPacketAndBuf1.packet;

	READ_FILE_INTO_BUFFER(2, "PacketExamples/Vxlan2.dat");

	pcpp::Packet vxlanPacket(rawPacket1.get());

	// test vxlan parsing
	pcpp::VxlanLayer* vxlanLayer = vxlanPacket.getLayerOfType<pcpp::VxlanLayer>();
	PTF_ASSERT_NOT_NULL(vxlanLayer);
	PTF_ASSERT_EQUAL(vxlanLayer->getVNI(), 3000001);
	PTF_ASSERT_EQUAL(vxlanLayer->getVxlanHeader()->groupPolicyID, htobe16(100));
	PTF_ASSERT_EQUAL(vxlanLayer->getVxlanHeader()->dontLearnFlag, 1);
	PTF_ASSERT_EQUAL(vxlanLayer->getVxlanHeader()->gbpFlag, 1);
	PTF_ASSERT_EQUAL(vxlanLayer->getVxlanHeader()->vniPresentFlag, 1);
	PTF_ASSERT_EQUAL(vxlanLayer->getVxlanHeader()->policyAppliedFlag, 1);
	PTF_ASSERT_NOT_NULL(vxlanLayer->getNextLayer());
	PTF_ASSERT_EQUAL(vxlanLayer->getNextLayer()->getProtocol(), pcpp::Ethernet, enum);

	// edit vxlan fields
	vxlanLayer->getVxlanHeader()->gbpFlag = 0;
	vxlanLayer->getVxlanHeader()->dontLearnFlag = 0;
	vxlanLayer->getVxlanHeader()->groupPolicyID = htobe16(32639);
	vxlanLayer->setVNI(300);

	vxlanPacket.computeCalculateFields();

	// verify edited fields
	PTF_ASSERT_EQUAL(vxlanPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(vxlanPacket.getRawPacket()->getRawData(), buffer2,
	                       vxlanPacket.getRawPacket()->getRawDataLen());

	// remove vxlan layer
	PTF_ASSERT_TRUE(vxlanPacket.removeLayer(pcpp::VXLAN));
	vxlanPacket.computeCalculateFields();

	// create new vxlan layer
	pcpp::VxlanLayer* newVxlanLayer = new pcpp::VxlanLayer(3000001, 100, true, true, true);
	PTF_ASSERT_TRUE(vxlanPacket.insertLayer(vxlanPacket.getLayerOfType<pcpp::UdpLayer>(), newVxlanLayer, true));

	// verify new vxlan layer
	PTF_ASSERT_EQUAL(vxlanPacket.getRawPacket()->getRawDataLen(), resource1.length);
	PTF_ASSERT_BUF_COMPARE(vxlanPacket.getRawPacket()->getRawData(), resource1.data.get(),
	                       vxlanPacket.getRawPacket()->getRawDataLen());

	delete[] buffer2;
}  // VxlanParsingAndCreationTest
