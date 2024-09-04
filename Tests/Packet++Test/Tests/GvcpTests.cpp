#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "GeneralUtils.h"
#include "GvcpLayer.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "UdpLayer.h"
#include <vector>

PTF_TEST_CASE(GvcpBasicTest)
{
	using namespace pcpp;

	{
		std::vector<uint8_t> payload = { 0x00, 0x01, 0x02, 0x03 };
		GvcpRequestLayer gvcpRequestLayer(GvcpCommand::DiscoveredCmd, payload.data(), payload.size(), 1, 2);
		PTF_ASSERT_EQUAL(gvcpRequestLayer.getProtocol(), Gvcp);

		GvcpRequestHeader* header = gvcpRequestLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredCmd);
		PTF_ASSERT_EQUAL(header->getFlag(), 1);
		PTF_ASSERT_EQUAL(header->getRequestId(), 2);
		PTF_ASSERT_EQUAL(header->getDataSize(), payload.size());
	}
	{
		std::vector<uint8_t> payload = { 0x00, 0x01, 0x02, 0x03 };
		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(GvcpResponseStatus::Success, GvcpCommand::DiscoveredAck,
		                                          payload.data(), payload.size(), 2);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader* header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getStatus(), GvcpResponseStatus::Success);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredAck);
		PTF_ASSERT_EQUAL(header->getAckId(), 2);
		PTF_ASSERT_EQUAL(header->getDataSize(), payload.size());
	}
}

PTF_TEST_CASE(GvcpDiscoveryCommand)
{
	// test the creation from the raw buffer
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_discovery_cmd.dat");
		pcpp::Packet discoverRequestPacket(&rawPacket1);

		auto udpLayer = discoverRequestPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a gvcpRequestLayer from the buffer
		GvcpDiscoveryRequestLayer gvcpRequestLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpRequestLayer.getProtocol(), Gvcp);
		GvcpRequestHeader* header = gvcpRequestLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint8_t(header->getFlag()), uint8_t(0x11));  // allow broadcast, acknowledge required
		PTF_ASSERT_EQUAL(header->hasAcknowledgeFlag(), true);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredCmd);
		PTF_ASSERT_EQUAL(header->verifyMagicNumber(), true);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpRequestLayer.getLayerPayloadSize());
	}

	// test the GVCP layer directly from the packet
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_discovery_cmd.dat");
		pcpp::Packet discoverCmdPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpRequestLayer = discoverCmdPacket.getLayerOfType<pcpp::GvcpDiscoveryRequestLayer>();

		PTF_ASSERT_EQUAL(gvcpRequestLayer->getProtocol(), Gvcp);
		GvcpRequestHeader* header = gvcpRequestLayer->getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(uint8_t(header->getFlag()), uint8_t(0x11));  // allow broadcast, acknowledge required
		PTF_ASSERT_EQUAL(header->hasAcknowledgeFlag(), true);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredCmd);
		PTF_ASSERT_EQUAL(header->verifyMagicNumber(), true);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpRequestLayer->getLayerPayloadSize());
	}
}

PTF_TEST_CASE(GvcpDiscoveryAck)
{
	// test the creation from the raw buffer
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_discovery_ack.dat");
		pcpp::Packet discoverAckPacket(&rawPacket1);

		auto udpLayer = discoverAckPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a GvcpAcknowledgeLayer from the buffer
		GvcpDiscoveryAcknowledgeLayer gvcpAcknowledgeLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader* header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getStatus(), GvcpResponseStatus::Success);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredAck);
		PTF_ASSERT_EQUAL(header->getAckId(), 1);
		PTF_ASSERT_EQUAL(header->getDataSize(), udpLayer->getLayerPayloadSize() - sizeof(GvcpAckHeader));

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getMacAddress(), pcpp::MacAddress("00:04:4b:ea:b0:b4"));
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getIpAddress(), pcpp::IPv4Address("172.28.60.100"));
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getManufacturerName(), "Vendor01");
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getModelName(), "ABCDE 3D Scanner (TW)");
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getSerialNumber(), "XXX-005");
	}

	// test the GVCP layer directly from the packet
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_discovery_ack.dat");
		pcpp::Packet discoverAckPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpAcknowledgeLayer = discoverAckPacket.getLayerOfType<pcpp::GvcpDiscoveryAcknowledgeLayer>();

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getProtocol(), Gvcp);
		GvcpAckHeader* header = gvcpAcknowledgeLayer->getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getStatus(), GvcpResponseStatus::Success);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::DiscoveredAck);
		PTF_ASSERT_EQUAL(header->getAckId(), 1);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpAcknowledgeLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getMacAddress(), pcpp::MacAddress("00:04:4b:ea:b0:b4"));
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getIpAddress(), pcpp::IPv4Address("172.28.60.100"));
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getManufacturerName(), "Vendor01");
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getModelName(), "ABCDE 3D Scanner (TW)");
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getSerialNumber(), "XXX-005");
	}
}

PTF_TEST_CASE(GvcpForceIpCommand)
{
	// test the creation from the raw buffer
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_forceip_cmd.dat");
		pcpp::Packet discoverAckPacket(&rawPacket1);

		auto udpLayer = discoverAckPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a GvcpRequestLayer from the buffer
		GvcpForceIpRequestLayer gvcpRequestLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpRequestLayer.getProtocol(), Gvcp);
		GvcpRequestHeader* header = gvcpRequestLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::ForceIpCmd);
		PTF_ASSERT_EQUAL(header->getDataSize(), udpLayer->getLayerPayloadSize() - sizeof(GvcpRequestHeader));
		PTF_ASSERT_EQUAL(header->getRequestId(), 8787);

		PTF_ASSERT_EQUAL(gvcpRequestLayer.getMacAddress(), pcpp::MacAddress("8c:e9:b4:01:63:b2"));
		PTF_ASSERT_EQUAL(gvcpRequestLayer.getIpAddress(), pcpp::IPv4Address("192.168.5.1"));
		PTF_ASSERT_EQUAL(gvcpRequestLayer.getSubnetMask(), pcpp::IPv4Address("255.255.0.0"));
		PTF_ASSERT_EQUAL(gvcpRequestLayer.getGatewayIpAddress(), pcpp::IPv4Address("0.0.0.0"));
	}

	// test the GVCP layer directly from the packet
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_forceip_cmd.dat");
		pcpp::Packet forceIpCommandPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpRequestLayer = forceIpCommandPacket.getLayerOfType<pcpp::GvcpForceIpRequestLayer>();

		PTF_ASSERT_EQUAL(gvcpRequestLayer->getProtocol(), Gvcp);
		GvcpRequestHeader* header = gvcpRequestLayer->getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::ForceIpCmd);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpRequestLayer->getLayerPayloadSize());
		PTF_ASSERT_EQUAL(header->getRequestId(), 8787);

		PTF_ASSERT_EQUAL(gvcpRequestLayer->getMacAddress(), pcpp::MacAddress("8c:e9:b4:01:63:b2"));
		PTF_ASSERT_EQUAL(gvcpRequestLayer->getIpAddress(), pcpp::IPv4Address("192.168.5.1"));
		PTF_ASSERT_EQUAL(gvcpRequestLayer->getSubnetMask(), pcpp::IPv4Address("255.255.0.0"));
		PTF_ASSERT_EQUAL(gvcpRequestLayer->getGatewayIpAddress(), pcpp::IPv4Address("0.0.0.0"));
	}
}

PTF_TEST_CASE(GvcpForceIpAck)
{
	// test the creation from the raw buffer
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_forceip_ack.dat");
		pcpp::Packet forceIpAckPacket(&rawPacket1);

		auto udpLayer = forceIpAckPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a GvcpAcknowledgeLayer from the buffer
		GvcpForceIpAcknowledgeLayer gvcpAcknowledgeLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		GvcpAckHeader* header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getStatus(), GvcpResponseStatus::Success);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::ForceIpAck);
		PTF_ASSERT_EQUAL(header->getAckId(), 8787);
		PTF_ASSERT_EQUAL(header->getDataSize(), 0);
	}

	// test the GVCP layer directly from the packet
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_forceip_ack.dat");
		pcpp::Packet forceIpAckPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpAcknowledgeLayer = forceIpAckPacket.getLayerOfType<pcpp::GvcpForceIpAcknowledgeLayer>();

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getProtocol(), Gvcp);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getStatus(), GvcpResponseStatus::Success);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getCommand(), GvcpCommand::ForceIpAck);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getAckId(), 8787);
		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getDataSize(), 0);
	}
}

PTF_TEST_CASE(GvcpReadRegisterCommand)
{
	// test the creation from the raw buffer
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_readreg_cmd.dat");
		pcpp::Packet readRegCmdPacket(&rawPacket1);

		auto udpLayer = readRegCmdPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a GvcpRequestLayer from the buffer
		GvcpRequestLayer gvcpRequestLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpRequestLayer.getProtocol(), Gvcp);
		GvcpRequestHeader* header = gvcpRequestLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::ReadRegCmd);
		PTF_ASSERT_EQUAL(header->getDataSize(), udpLayer->getLayerPayloadSize() - sizeof(GvcpRequestHeader));
		PTF_ASSERT_EQUAL(header->getRequestId(), 35824);

		auto payload = gvcpRequestLayer.getLayerPayload();
		PTF_ASSERT_TRUE(payload != nullptr);
		PTF_ASSERT_EQUAL(reinterpret_cast<uint32_t*>(payload)[0], 0x00000000);
	}

	// test the GVCP layer directly from the packet
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_readreg_cmd.dat");
		pcpp::Packet readRegCmdPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpRequestLayer = readRegCmdPacket.getLayerOfType<pcpp::GvcpRequestLayer>();

		PTF_ASSERT_EQUAL(gvcpRequestLayer->getProtocol(), Gvcp);
		GvcpRequestHeader* header = gvcpRequestLayer->getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::ReadRegCmd);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpRequestLayer->getLayerPayloadSize());
		PTF_ASSERT_EQUAL(header->getRequestId(), 35824);

		auto payload = gvcpRequestLayer->getLayerPayload();
		PTF_ASSERT_TRUE(payload != nullptr);
		PTF_ASSERT_EQUAL(reinterpret_cast<uint32_t*>(payload)[0], 0x00000000);
	}
}

PTF_TEST_CASE(GvcpReadRegisterAcknowledge)
{
	// test the creation from the raw buffer
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_readreg_ack.dat");
		pcpp::Packet readRegAckPacket(&rawPacket1);

		auto udpLayer = readRegAckPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a GvcpAcknowledgeLayer from the buffer
		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		auto header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getAckId(), 0x1fee);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::ReadRegAck);
		PTF_ASSERT_EQUAL(header->getDataSize(), udpLayer->getLayerPayloadSize() - sizeof(GvcpAckHeader));
		PTF_ASSERT_EQUAL(header->getStatus(), 0x0000);

		auto payload = gvcpAcknowledgeLayer.getLayerPayload();
		PTF_ASSERT_TRUE(payload != nullptr);
		PTF_ASSERT_EQUAL(reinterpret_cast<uint32_t*>(payload)[0], hostToNet32(0x80000001));
	}

	// test the GVCP layer directly from the packet
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_readreg_ack.dat");
		pcpp::Packet readRegAckPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpAcknowledgeLayer = readRegAckPacket.getLayerOfType<pcpp::GvcpAcknowledgeLayer>();

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getProtocol(), Gvcp);
		auto header = gvcpAcknowledgeLayer->getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getAckId(), 0x1fee);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::ReadRegAck);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpAcknowledgeLayer->getLayerPayloadSize());
		PTF_ASSERT_EQUAL(header->getStatus(), 0x0000);

		auto payload = gvcpAcknowledgeLayer->getLayerPayload();
		PTF_ASSERT_TRUE(payload != nullptr);
		PTF_ASSERT_EQUAL(reinterpret_cast<uint32_t*>(payload)[0], hostToNet32(0x80000001));
	}
}

PTF_TEST_CASE(GvcpWriteRegisterCommand)
{
	// test the creation from the raw buffer
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_writereg_cmd.dat");
		pcpp::Packet writeRegCmdPacket(&rawPacket1);

		auto udpLayer = writeRegCmdPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a GvcpRequestLayer from the buffer
		GvcpRequestLayer gvcpRequestLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpRequestLayer.getProtocol(), Gvcp);
		GvcpRequestHeader* header = gvcpRequestLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::WriteRegCmd);
		PTF_ASSERT_EQUAL(header->getDataSize(), udpLayer->getLayerPayloadSize() - sizeof(GvcpRequestHeader));
		PTF_ASSERT_EQUAL(header->getRequestId(), 8788);

		auto payload = gvcpRequestLayer.getLayerPayload();
		PTF_ASSERT_TRUE(payload != nullptr);
		auto payloadHex = pcpp::byteArrayToHexString(payload, gvcpRequestLayer.getLayerPayloadSize(), -1);
		const std::string correctPayload = "00000a00000000020000064cc0a805010000065cffff00000000001400000005";
		PTF_ASSERT_EQUAL(payloadHex, correctPayload);
	}

	// test the GVCP layer directly from the packet
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_writereg_cmd.dat");
		pcpp::Packet writeRegCmdPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpRequestLayer = writeRegCmdPacket.getLayerOfType<pcpp::GvcpRequestLayer>();

		PTF_ASSERT_EQUAL(gvcpRequestLayer->getProtocol(), Gvcp);
		GvcpRequestHeader* header = gvcpRequestLayer->getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::WriteRegCmd);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpRequestLayer->getLayerPayloadSize());
		PTF_ASSERT_EQUAL(header->getRequestId(), 8788);

		auto payload = gvcpRequestLayer->getLayerPayload();
		PTF_ASSERT_TRUE(payload != nullptr);
		auto payloadHex = pcpp::byteArrayToHexString(payload, gvcpRequestLayer->getLayerPayloadSize(), -1);
		const std::string correctPayload = "00000a00000000020000064cc0a805010000065cffff00000000001400000005";
		PTF_ASSERT_EQUAL(payloadHex, correctPayload);
	}
}

PTF_TEST_CASE(GvcpWriteRegisterAcknowledge)
{
	// test the creation from the raw buffer
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_writereg_ack.dat");
		pcpp::Packet writeRegAckPacket(&rawPacket1);

		auto udpLayer = writeRegAckPacket.getLayerOfType<pcpp::UdpLayer>();

		// we get the raw buffer from the payload of the UDP layer and create a GvcpAcknowledgeLayer from the buffer
		GvcpAcknowledgeLayer gvcpAcknowledgeLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer.getProtocol(), Gvcp);
		auto header = gvcpAcknowledgeLayer.getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getAckId(), 8788);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::WriteRegAck);
		PTF_ASSERT_EQUAL(header->getDataSize(), udpLayer->getLayerPayloadSize() - sizeof(GvcpAckHeader));
		PTF_ASSERT_EQUAL(header->getStatus(), 0x8006);
	}

	// test the GVCP layer directly from the packet
	{
		using namespace pcpp;

		timeval time;
		gettimeofday(&time, nullptr);
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/gvcp_writereg_ack.dat");
		pcpp::Packet writeRegAckPacket(&rawPacket1);

		// we get the GVCP layer from the packet
		auto gvcpAcknowledgeLayer = writeRegAckPacket.getLayerOfType<pcpp::GvcpAcknowledgeLayer>();

		PTF_ASSERT_EQUAL(gvcpAcknowledgeLayer->getProtocol(), Gvcp);
		auto header = gvcpAcknowledgeLayer->getGvcpHeader();
		PTF_ASSERT_TRUE(header != nullptr);
		PTF_ASSERT_EQUAL(header->getAckId(), 8788);
		PTF_ASSERT_EQUAL(header->getCommand(), GvcpCommand::WriteRegAck);
		PTF_ASSERT_EQUAL(header->getDataSize(), gvcpAcknowledgeLayer->getLayerPayloadSize());
		PTF_ASSERT_EQUAL(header->getStatus(), 0x8006);
	}
}
