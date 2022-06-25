#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "StpLayer.h"

PTF_TEST_CASE(StpConfigurationParsingTests)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/StpConf.dat");

	pcpp::Packet stpPacket(&rawPacket1);
	pcpp::StpConfigurationBPDULayer *stpConfLayer = stpPacket.getLayerOfType<pcpp::StpConfigurationBPDULayer>();

	PTF_ASSERT_NOT_NULL(stpConfLayer);

	// Stp Configuration Layer Tests
	PTF_ASSERT_EQUAL(stpConfLayer->getProtoId(), 0x0);
	PTF_ASSERT_EQUAL(stpConfLayer->getVersion(), 0x0);
	PTF_ASSERT_EQUAL(stpConfLayer->getType(), 0x0);
	PTF_ASSERT_EQUAL(stpConfLayer->getFlag(), 0x0);
	PTF_ASSERT_EQUAL(stpConfLayer->getRootId(), be64toh(0x8064001c0e877800));
	PTF_ASSERT_EQUAL(stpConfLayer->getPathCost(), 0x4);
	PTF_ASSERT_EQUAL(stpConfLayer->getPortId(), be16toh(0x8004));
	PTF_ASSERT_EQUAL(stpConfLayer->getMessageAge(), 0x1);
	PTF_ASSERT_EQUAL(stpConfLayer->getMaximumAge(), 0x14);
	PTF_ASSERT_EQUAL(stpConfLayer->getTransmissionInterval(), 0x2);
	PTF_ASSERT_EQUAL(stpConfLayer->getForwardDelay(), 0x0f);

	PTF_ASSERT_EQUAL(stpConfLayer->toString(), "Spanning Tree Configuration");
}

PTF_TEST_CASE(StpTopologyChangeParsingTests)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/StpTcn.dat");

	pcpp::Packet stpPacket(&rawPacket1);
	pcpp::StpTopologyChangeBPDULayer *stpTopologyLayer = stpPacket.getLayerOfType<pcpp::StpTopologyChangeBPDULayer>();

	PTF_ASSERT_NOT_NULL(stpTopologyLayer);

	// Stp Topology Change Layer Tests
	PTF_ASSERT_EQUAL(stpTopologyLayer->getProtoId(), 0x0);
	PTF_ASSERT_EQUAL(stpTopologyLayer->getVersion(), 0x0);
	PTF_ASSERT_EQUAL(stpTopologyLayer->getType(), 0x80);

	PTF_ASSERT_EQUAL(stpTopologyLayer->toString(), "Spanning Tree Topology Change Notification");
}

PTF_TEST_CASE(RapidStpParsingTests)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/StpRapid.dat");

	pcpp::Packet stpPacket(&rawPacket1);
	pcpp::RapidStpLayer *stpRapidLayer = stpPacket.getLayerOfType<pcpp::RapidStpLayer>();

	PTF_ASSERT_NOT_NULL(stpRapidLayer);

	// Rapid Stp Layer Tests
	PTF_ASSERT_EQUAL(stpRapidLayer->getProtoId(), 0x0);
	PTF_ASSERT_EQUAL(stpRapidLayer->getVersion(), 0x2);
	PTF_ASSERT_EQUAL(stpRapidLayer->getType(), 0x2);
	PTF_ASSERT_EQUAL(stpRapidLayer->getFlag(), 0x3d);
	PTF_ASSERT_EQUAL(stpRapidLayer->getRootId(), be64toh(0x6001000d65adf600));
	PTF_ASSERT_EQUAL(stpRapidLayer->getPathCost(), 0x0a);
	PTF_ASSERT_EQUAL(stpRapidLayer->getBridgeId(), be64toh(0x8001000bfd860f00));
	PTF_ASSERT_EQUAL(stpRapidLayer->getPortId(), be16toh(0x8001));
	PTF_ASSERT_EQUAL(stpRapidLayer->getMessageAge(), 0x1);
	PTF_ASSERT_EQUAL(stpRapidLayer->getMaximumAge(), 0x14);
	PTF_ASSERT_EQUAL(stpRapidLayer->getTransmissionInterval(), 0x2);
	PTF_ASSERT_EQUAL(stpRapidLayer->getVersion1Len(), 0x0);

	PTF_ASSERT_EQUAL(stpRapidLayer->toString(), "Rapid Spanning Tree");
}

PTF_TEST_CASE(MultipleStpParsingTests)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/StpMultiple.dat");

	pcpp::Packet stpPacket(&rawPacket1);
	pcpp::MultipleStpLayer *stpMultipleLayer = stpPacket.getLayerOfType<pcpp::MultipleStpLayer>();

	PTF_ASSERT_NOT_NULL(stpMultipleLayer);

	// Multiple Stp Tests
	PTF_ASSERT_EQUAL(stpMultipleLayer->getProtoId(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getVersion(), 0x3);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getType(), 0x2);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getFlag(), 0x7c);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getRootId(), be64toh(0x8000000c305dd100));
	PTF_ASSERT_EQUAL(stpMultipleLayer->getPathCost(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getBridgeId(), be64toh(0x8000000c305dd100));
	PTF_ASSERT_EQUAL(stpMultipleLayer->getPortId(), be16toh(0x8005));
	PTF_ASSERT_EQUAL(stpMultipleLayer->getMessageAge(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getMaximumAge(), 0x14);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getTransmissionInterval(), 0x2);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getVersion1Len(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getVersion3Len(), 0x50);

	PTF_ASSERT_EQUAL(stpMultipleLayer->getMstConfigurationFormatSelector(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getMstConfigurationName(), std::string());
	PTF_ASSERT_EQUAL(stpMultipleLayer->getMstConfigRevision(), 0x0);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getCISTIrpc(), 0x00030d40);
	PTF_ASSERT_EQUAL(stpMultipleLayer->getCISTBridgeId(), be64toh(0x8000001aa197d180));
	PTF_ASSERT_EQUAL(stpMultipleLayer->getRemainingHopCount(), 0x13);

	PTF_ASSERT_EQUAL(stpMultipleLayer->getNumberOfMSTIConfMessages(), 1);

	pcpp::msti_conf_msg *ptrExtension = stpMultipleLayer->getMstiConfMessages();
	PTF_ASSERT_NOT_NULL(ptrExtension);

	PTF_ASSERT_EQUAL(ptrExtension->flags, 0x7c);
	PTF_ASSERT_EQUAL(ptrExtension->regionalRootId, be64toh(0x8005000c305dd100));
	PTF_ASSERT_EQUAL(ptrExtension->pathCost, be32toh(0x00030d40));
	PTF_ASSERT_EQUAL(ptrExtension->bridgePriority, 0x80);
	PTF_ASSERT_EQUAL(ptrExtension->portPriority, 0x80);
	PTF_ASSERT_EQUAL(ptrExtension->remainingHops, 0x13);

	PTF_ASSERT_EQUAL(stpMultipleLayer->toString(), "Multiple Spanning Tree");
}
