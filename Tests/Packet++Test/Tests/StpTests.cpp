#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "StpLayer.h"

PTF_TEST_CASE(StpConfigurationParsingTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/StpConf.dat");

	pcpp::Packet stpPacket(&rawPacket1);
	PTF_ASSERT_TRUE(stpPacket.isPacketOfType(pcpp::STP));

	pcpp::StpConfigurationBPDULayer *stpConfLayer = stpPacket.getLayerOfType<pcpp::StpConfigurationBPDULayer>();
	PTF_ASSERT_NOT_NULL(stpConfLayer);

	// Stp Configuration Layer Tests
	PTF_ASSERT_EQUAL(stpConfLayer->getProtoId(), 0x0);
	PTF_ASSERT_EQUAL(stpConfLayer->getVersion(), 0x0);
	PTF_ASSERT_EQUAL(stpConfLayer->getType(), 0x0);
	PTF_ASSERT_EQUAL(stpConfLayer->getFlag(), 0x0);
	PTF_ASSERT_EQUAL(stpConfLayer->getRootId(), 0x8064001c0e877800);
	PTF_ASSERT_EQUAL(stpConfLayer->getRootPriority(), 32768);
	PTF_ASSERT_EQUAL(stpConfLayer->getRootSystemIDExtension(), 100);
	PTF_ASSERT_EQUAL(stpConfLayer->getRootSystemID(), pcpp::MacAddress("00:1c:0e:87:78:00"));
	PTF_ASSERT_EQUAL(stpConfLayer->getPathCost(), 0x4);
	PTF_ASSERT_EQUAL(stpConfLayer->getBridgeId(), 0x8064001c0e878500);
	PTF_ASSERT_EQUAL(stpConfLayer->getBridgePriority(), 32768);
	PTF_ASSERT_EQUAL(stpConfLayer->getBridgeSystemIDExtension(), 100);
	PTF_ASSERT_EQUAL(stpConfLayer->getBridgeSystemID(), pcpp::MacAddress("00:1c:0e:87:85:00"));
	PTF_ASSERT_EQUAL(stpConfLayer->getPortId(), 0x8004);
	PTF_ASSERT_EQUAL(stpConfLayer->getMessageAge(), 1);
	PTF_ASSERT_EQUAL(stpConfLayer->getMaximumAge(), 20);
	PTF_ASSERT_EQUAL(stpConfLayer->getTransmissionInterval(), 2);
	PTF_ASSERT_EQUAL(stpConfLayer->getForwardDelay(), 15);

	PTF_ASSERT_EQUAL(stpConfLayer->toString(), "Spanning Tree Configuration");
} // StpConfigurationParsingTests

PTF_TEST_CASE(StpTopologyChangeParsingTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/StpTcn.dat");

	pcpp::Packet stpPacket(&rawPacket1);
	PTF_ASSERT_TRUE(stpPacket.isPacketOfType(pcpp::STP));

	pcpp::StpTopologyChangeBPDULayer *stpTopologyLayer = stpPacket.getLayerOfType<pcpp::StpTopologyChangeBPDULayer>();
	PTF_ASSERT_NOT_NULL(stpTopologyLayer);

	// Stp Topology Change Layer Tests
	PTF_ASSERT_EQUAL(stpTopologyLayer->getProtoId(), 0x0);
	PTF_ASSERT_EQUAL(stpTopologyLayer->getVersion(), 0x0);
	PTF_ASSERT_EQUAL(stpTopologyLayer->getType(), 0x80);

	PTF_ASSERT_EQUAL(stpTopologyLayer->toString(), "Spanning Tree Topology Change Notification");
} // StpTopologyChangeParsingTests

PTF_TEST_CASE(RapidStpParsingTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/StpRapid.dat");

	pcpp::Packet stpPacket(&rawPacket1);
	PTF_ASSERT_TRUE(stpPacket.isPacketOfType(pcpp::STP));

	pcpp::RapidStpLayer *stpRapidLayer = stpPacket.getLayerOfType<pcpp::RapidStpLayer>();
	PTF_ASSERT_NOT_NULL(stpRapidLayer);

	// Rapid Stp Layer Tests
	PTF_ASSERT_EQUAL(stpRapidLayer->getProtoId(), 0x0);
	PTF_ASSERT_EQUAL(stpRapidLayer->getVersion(), 0x2);
	PTF_ASSERT_EQUAL(stpRapidLayer->getType(), 0x2);
	PTF_ASSERT_EQUAL(stpRapidLayer->getFlag(), 0x3d);
	PTF_ASSERT_EQUAL(stpRapidLayer->getRootId(), 0x6001000d65adf600);
	PTF_ASSERT_EQUAL(stpRapidLayer->getRootPriority(), 24576);
	PTF_ASSERT_EQUAL(stpRapidLayer->getRootSystemIDExtension(), 1);
	PTF_ASSERT_EQUAL(stpRapidLayer->getRootSystemID(), pcpp::MacAddress("00:0d:65:ad:f6:00"));
	PTF_ASSERT_EQUAL(stpRapidLayer->getPathCost(), 0x0a);
	PTF_ASSERT_EQUAL(stpRapidLayer->getBridgeId(), 0x8001000bfd860f00);
	PTF_ASSERT_EQUAL(stpRapidLayer->getBridgePriority(), 32768);
	PTF_ASSERT_EQUAL(stpRapidLayer->getBridgeSystemIDExtension(), 1);
	PTF_ASSERT_EQUAL(stpRapidLayer->getBridgeSystemID(), pcpp::MacAddress("00:0b:fd:86:0f:00"));
	PTF_ASSERT_EQUAL(stpRapidLayer->getPortId(), 0x8001);
	PTF_ASSERT_EQUAL(stpRapidLayer->getMessageAge(), 1);
	PTF_ASSERT_EQUAL(stpRapidLayer->getMaximumAge(), 20);
	PTF_ASSERT_EQUAL(stpRapidLayer->getTransmissionInterval(), 2);
	PTF_ASSERT_EQUAL(stpRapidLayer->getForwardDelay(), 15);
	PTF_ASSERT_EQUAL(stpRapidLayer->getVersion1Len(), 0);

	PTF_ASSERT_EQUAL(stpRapidLayer->toString(), "Rapid Spanning Tree");
} // RapidStpParsingTests

PTF_TEST_CASE(MultipleStpParsingTests)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/StpMultiple.dat");

	pcpp::Packet stpPacket(&rawPacket1);
	PTF_ASSERT_TRUE(stpPacket.isPacketOfType(pcpp::STP));

	pcpp::MultipleStpLayer *stpMultipleLayer = stpPacket.getLayerOfType<pcpp::MultipleStpLayer>();
	PTF_ASSERT_NOT_NULL(stpMultipleLayer);

	// Multiple Stp Tests
	PTF_ASSERT_EQUAL(stpMultipleLayer->getProtoId(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getVersion(), 0x3);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getType(), 0x2);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getFlag(), 0x7c);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getRootId(), 0x8000000c305dd100);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getRootPriority(), 32768);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getRootSystemIDExtension(), 0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getRootSystemID(), pcpp::MacAddress("00:0c:30:5d:d1:00"));
	PTF_ASSERT_EQUAL(stpMultipleLayer->getPathCost(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getBridgeId(), 0x8000000c305dd100);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getBridgePriority(), 32768);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getBridgeSystemIDExtension(), 0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getBridgeSystemID(), pcpp::MacAddress("00:0c:30:5d:d1:00"));
	PTF_ASSERT_EQUAL(stpMultipleLayer->getPortId(), 0x8005);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getMessageAge(), 0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getMaximumAge(), 20);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getTransmissionInterval(), 2);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getForwardDelay(), 15);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getVersion1Len(), 0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getVersion3Len(), 80);

	PTF_ASSERT_EQUAL(stpMultipleLayer->getMstConfigurationFormatSelector(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getMstConfigurationName(), std::string());
	PTF_ASSERT_EQUAL(stpMultipleLayer->getMstConfigRevision(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getCISTIrpc(), 200000);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getCISTBridgeId(), 0x8000001aa197d180);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getCISTBridgePriority(), 32768);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getCISTBridgeSystemIDExtension(), 0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getCISTBridgeSystemID(), pcpp::MacAddress("00:1a:a1:97:d1:80"));
	PTF_ASSERT_EQUAL(stpMultipleLayer->getRemainingHopCount(), 19);

	PTF_ASSERT_EQUAL(stpMultipleLayer->getNumberOfMSTIConfMessages(), 1);

	pcpp::msti_conf_msg *ptrExtension = stpMultipleLayer->getMstiConfMessages();
	PTF_ASSERT_NOT_NULL(ptrExtension);

	PTF_ASSERT_EQUAL(ptrExtension->flags, 0x7c);
	PTF_ASSERT_EQUAL(ptrExtension->regionalRootId, be64toh(0x8005000c305dd100));
	PTF_ASSERT_EQUAL(ptrExtension->pathCost, be32toh(200000));
	PTF_ASSERT_EQUAL(ptrExtension->bridgePriority, 8 << 4);
	PTF_ASSERT_EQUAL(ptrExtension->portPriority, 8 << 4);
	PTF_ASSERT_EQUAL(ptrExtension->remainingHops, 19);

	PTF_ASSERT_EQUAL(stpMultipleLayer->toString(), "Multiple Spanning Tree");
} // MultipleStpParsingTests
