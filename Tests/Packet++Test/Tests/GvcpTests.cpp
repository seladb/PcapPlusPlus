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
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredCmd);
		PTF_ASSERT_EQUAL(header->getFlag(), 1);
		PTF_ASSERT_EQUAL(header->getRequestId(), 2);
		PTF_ASSERT_EQUAL(header->getDataSize(), payload.size());
	}
	{
		std::vector<uint8_t> payload = {0x00, 0x01, 0x02, 0x03};
		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(GvcpResponseStatus::Success, GvcpCommand::DiscoveredAck,
												  payload.data(), payload.size(), 2);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader *header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getStatus(), GvcpResponseStatus::Success);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredAck);
		PTF_ASSERT_EQUAL(header->getAckId(), 2);
		PTF_ASSERT_EQUAL(header->getDataSize(), payload.size());
	}
}

PTF_TEST_CASE(GvcpDiscoveryAck)
{
	// test the creation from the raw buffer
	try
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_discovery_ack.dat");
		pcpp::Packet discoverAckPacket(&rawPacket1);

		auto udpLayer = discoverAckPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a GvcpAcknowledgeLayer from the buffer
		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader *header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getStatus(), GvcpResponseStatus::Success);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredAck);
		PTF_ASSERT_EQUAL(header->getAckId(), 1);
		PTF_ASSERT_EQUAL(header->getDataSize(), udpLayer->getLayerPayloadSize() - sizeof(GvcpAckHeader));

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

	// test the GVCP layer directly from the packet
	try
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_discovery_ack.dat");
		pcpp::Packet discoverAckPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpAcknowledgeLayer = discoverAckPacket.getLayerOfType<pcpp::GvcpAcknowledgeLayer>();

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getProtocol(), Gvcp);
		GvcpAckHeader *header = gvcpAcknowledgeLayer->getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getStatus(), GvcpResponseStatus::Success);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredAck);
		PTF_ASSERT_EQUAL(header->getAckId(), 1);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpAcknowledgeLayer->getDataLen());

		auto discoveryBody = gvcpAcknowledgeLayer->getGvcpDiscoveryBody();
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

PTF_TEST_CASE(GvcpForceIpCommand)
{
	// test the creation from the raw buffer
	try
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_forceip_cmd.dat");
		pcpp::Packet discoverAckPacket(&rawPacket1);

		auto udpLayer = discoverAckPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a GvcpRequestLayer from the buffer
		GvcpRequestLayer gvcpRequestLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpRequestLayer.getProtocol(), Gvcp);
		GvcpRequestHeader *header = gvcpRequestLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::ForceIpCmd);
		PTF_ASSERT_EQUAL(header->getDataSize(), udpLayer->getLayerPayloadSize() - sizeof(GvcpRequestHeader));
		PTF_ASSERT_EQUAL(header->getRequestId(), 8787);

		auto forceIpBody = gvcpRequestLayer.getGvcpForceIpBody();
		PTF_ASSERT_TRUE(forceIpBody != nullptr);
		PTF_ASSERT_EQUAL(forceIpBody->getMacAddress(), pcpp::MacAddress("8c:e9:b4:01:63:b2"));
		PTF_ASSERT_EQUAL(forceIpBody->getIpAddress(), pcpp::IPv4Address("192.168.5.1"));
		PTF_ASSERT_EQUAL(forceIpBody->getSubnetMask(), pcpp::IPv4Address("255.255.0.0"));
		PTF_ASSERT_EQUAL(forceIpBody->getGatewayIpAddress(), pcpp::IPv4Address("0.0.0.0"));
	}
	catch (...)
	{
		std::cout << "Exception occurred" << std::endl;
	}

	// test the GVCP layer directly from the packet
	try
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_forceip_cmd.dat");
		pcpp::Packet forceIpCommandPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpRequestLayer = forceIpCommandPacket.getLayerOfType<pcpp::GvcpRequestLayer>();

		PTF_ASSERT_EQUAL(gvcpRequestLayer->getProtocol(), Gvcp);
		GvcpRequestHeader *header = gvcpRequestLayer->getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::ForceIpCmd);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpRequestLayer->getDataLen());
		PTF_ASSERT_EQUAL(header->getRequestId(), 8787);

		auto forceIpBody = gvcpRequestLayer->getGvcpForceIpBody();
		PTF_ASSERT_TRUE(forceIpBody != nullptr);
		PTF_ASSERT_EQUAL(forceIpBody->getMacAddress(), pcpp::MacAddress("8c:e9:b4:01:63:b2"));
		PTF_ASSERT_EQUAL(forceIpBody->getIpAddress(), pcpp::IPv4Address("192.168.5.1"));
		PTF_ASSERT_EQUAL(forceIpBody->getSubnetMask(), pcpp::IPv4Address("255.255.0.0"));
		PTF_ASSERT_EQUAL(forceIpBody->getGatewayIpAddress(), pcpp::IPv4Address("0.0.0.0"));
	}
	catch (...)
	{
		std::cout << "Exception occurred" << std::endl;
	}
}