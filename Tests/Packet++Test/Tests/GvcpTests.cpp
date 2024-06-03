#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "GvcpLayer.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "UdpLayer.h"
#include <vector>

PTF_TEST_CASE(GvcpBasicTest)
{
	using namespace pcpp;

	{
		std::vector<uint8_t> payload = {0x00, 0x01, 0x02, 0x03};
		GvcpRequestLayer gvcpRequestLayer(GvcpCommand::DiscoveredCmd, payload.data(), payload.size(), 1, 2);
		PTF_ASSERT_EQUAL(gvcpRequestLayer.getProtocol(), Gvcp);

		GvcpRequestHeader *header = gvcpRequestLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint16_t(header->command), uint16_t(GvcpCommand::DiscoveredCmd));
		PTF_ASSERT_EQUAL(header->flag, 1);
		PTF_ASSERT_EQUAL(header->requestId, 2);
		PTF_ASSERT_EQUAL(header->dataSize, payload.size());
	}
	{
		std::vector<uint8_t> payload = {0x00, 0x01, 0x02, 0x03};
		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(GvcpResponseStatus::Success, GvcpCommand::DiscoveredAck,
												  payload.data(), payload.size(), 2);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader *header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint16_t(header->status), uint16_t(GvcpResponseStatus::Success));
		PTF_ASSERT_EQUAL(uint16_t(header->command), uint16_t(GvcpCommand::DiscoveredAck));
		PTF_ASSERT_EQUAL(header->ackId, 2);
		PTF_ASSERT_EQUAL(header->dataSize, payload.size());
	}
}

PTF_TEST_CASE(GvcpDiscoveryAck)
{
	try
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_discovery_ack.dat");
		pcpp::Packet discoverAckPacket(&rawPacket1);

		auto udpLayer = discoverAckPacket.getLayerOfType<pcpp::UdpLayer>();

		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader *header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint16_t(header->status), uint16_t(GvcpResponseStatus::Success));
		PTF_ASSERT_EQUAL(uint16_t(header->command), uint16_t(GvcpCommand::DiscoveredAck));
		PTF_ASSERT_EQUAL(header->ackId, 1);
		PTF_ASSERT_EQUAL(header->dataSize, udpLayer->getLayerPayloadSize() - sizeof(GvcpAckHeader));

		auto discoveryBody = gvcpAcknowledgeLayer.getGvcpDiscoveryBody();
		PTF_ASSERT_TRUE(discoveryBody != nullptr);
		PTF_ASSERT_EQUAL(discoveryBody->getMacAddress(), pcpp::MacAddress("00:04:4b:ea:b0:b4"));
		PTF_ASSERT_EQUAL(discoveryBody->getIpAddress(), pcpp::IPv4Address("172.28.60.100"));
		PTF_ASSERT_EQUAL(discoveryBody->getManufacturerName(), "Vendor01");
		PTF_ASSERT_EQUAL(discoveryBody->getModelName(), "ABCDE 3D Scanner (TW)");
		PTF_ASSERT_EQUAL(discoveryBody->getSerialNumber(), "XXX-005");
	}
	catch (...)
	{
		std::cout << "Exception occurred" << std::endl;
	}
}