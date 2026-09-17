#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EthLayer.h"
#include "GeneralUtils.h"
#include "GvcpLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "UdpLayer.h"

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(GvcpDiscoveryParsingTest)
{
	// Discovery command
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_discovery_cmd.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpDiscoveryRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(gvcpLayer->getOsiModelLayer(), pcpp::OsiModelApplicationLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getFlag(), 0x11);  // allow broadcast, acknowledge required
		PTF_ASSERT_TRUE(gvcpLayer->hasAcknowledgeFlag());
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::DiscoveredCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getRequestId(), 19942);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 0);
		PTF_ASSERT_EQUAL(gvcpLayer->getHeaderLen(), 8);
		PTF_ASSERT_EQUAL(gvcpLayer->getPayloadDataLen(), 0);
		PTF_ASSERT_NULL(gvcpLayer->getPayloadData());
		PTF_ASSERT_NULL(gvcpLayer->getNextLayer());
		PTF_ASSERT_EQUAL(gvcpLayer->toString(), "GVCP Request Layer, Command: 0x2, Request ID: 19942");
	}

	// Discovery acknowledge
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_discovery_ack.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpDiscoveryAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpResponseStatus::Success, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::DiscoveredAck, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 1);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 248);
		PTF_ASSERT_EQUAL(gvcpLayer->getHeaderLen(), 256);
		PTF_ASSERT_EQUAL(gvcpLayer->getPayloadDataLen(), 248);
		PTF_ASSERT_NOT_NULL(gvcpLayer->getPayloadData());

		PTF_ASSERT_EQUAL(gvcpLayer->getMacAddress(), pcpp::MacAddress("00:04:4b:ea:b0:b4"));
		PTF_ASSERT_EQUAL(gvcpLayer->getIpAddress(), pcpp::IPv4Address("172.28.60.100"));
		PTF_ASSERT_EQUAL(gvcpLayer->getManufacturerName(), "Vendor01");
		PTF_ASSERT_EQUAL(gvcpLayer->getModelName(), "ABCDE 3D Scanner (TW)");
		PTF_ASSERT_EQUAL(gvcpLayer->getSerialNumber(), "XXX-005");
		PTF_ASSERT_EQUAL(gvcpLayer->toString(), "GVCP Acknowledge Layer, Command: 0x3, Acknowledge ID: 1, Status: 0x0");
	}
}  // GvcpDiscoveryParsingTest

PTF_TEST_CASE(GvcpForceIpParsingTest)
{
	// Force IP command
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_forceip_cmd.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpForceIpRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getFlag(), 0x01);
		PTF_ASSERT_TRUE(gvcpLayer->hasAcknowledgeFlag());
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::ForceIpCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getRequestId(), 8787);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 56);
		PTF_ASSERT_EQUAL(gvcpLayer->getPayloadDataLen(), 56);

		PTF_ASSERT_EQUAL(gvcpLayer->getMacAddress(), pcpp::MacAddress("8c:e9:b4:01:63:b2"));
		PTF_ASSERT_EQUAL(gvcpLayer->getIpAddress(), pcpp::IPv4Address("192.168.5.1"));
		PTF_ASSERT_EQUAL(gvcpLayer->getSubnetMask(), pcpp::IPv4Address("255.255.0.0"));
		PTF_ASSERT_EQUAL(gvcpLayer->getGatewayIpAddress(), pcpp::IPv4Address("0.0.0.0"));
	}

	// Force IP acknowledge
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_forceip_ack.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpForceIpAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpResponseStatus::Success, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::ForceIpAck, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 8787);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 0);
		PTF_ASSERT_EQUAL(gvcpLayer->getPayloadDataLen(), 0);
	}
}  // GvcpForceIpParsingTest

PTF_TEST_CASE(GvcpRegisterAccessParsingTest)
{
	// Read register command
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_readreg_cmd.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::ReadRegCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getRequestId(), 35824);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), gvcpLayer->getPayloadDataLen());
		PTF_ASSERT_EQUAL(pcpp::byteArrayToHexString(gvcpLayer->getPayloadData(), 4), "00000000");
	}

	// Read register acknowledge
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_readreg_ack.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpResponseStatus::Success, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::ReadRegAck, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 0x1fee);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), gvcpLayer->getPayloadDataLen());
		PTF_ASSERT_EQUAL(pcpp::byteArrayToHexString(gvcpLayer->getPayloadData(), 4), "80000001");
	}

	// Write register command
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_writereg_cmd.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::WriteRegCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getRequestId(), 8788);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), gvcpLayer->getPayloadDataLen());
		PTF_ASSERT_EQUAL(pcpp::byteArrayToHexString(gvcpLayer->getPayloadData(), gvcpLayer->getPayloadDataLen()),
		                 "00000a00000000020000064cc0a805010000065cffff00000000001400000005");
	}

	// Write register acknowledge with an error status
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_writereg_ack.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpResponseStatus::AccessDenied, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::WriteRegAck, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 8788);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 0);
		PTF_ASSERT_EQUAL(gvcpLayer->getPayloadDataLen(), 0);
		PTF_ASSERT_EQUAL(gvcpLayer->toString(),
		                 "GVCP Acknowledge Layer, Command: 0x83, Acknowledge ID: 8788, Status: 0x8006");
	}
}  // GvcpRegisterAccessParsingTest

PTF_TEST_CASE(GvcpMalformedParsingTest)
{
	// The data is too short to hold a GVCP header, so it must not be parsed as GVCP
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_truncated.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_FALSE(packet.isPacketOfType(pcpp::GVCP));
		PTF_ASSERT_NULL(packet.getLayerOfType<pcpp::GvcpLayer>());
		PTF_ASSERT_NOT_NULL(packet.getLayerOfType<pcpp::PayloadLayer>());
	}

	// A force IP command which is too short to hold the force IP body is parsed as a generic request
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_forceip_cmd_short.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));
		PTF_ASSERT_NULL(packet.getLayerOfType<pcpp::GvcpForceIpRequestLayer>());

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::ForceIpCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getPayloadDataLen(), 8);
	}

	// Unknown command and status values
	{
		uint8_t payload[] = { 0x00, 0x01 };
		pcpp::GvcpRequestLayer requestLayer(static_cast<pcpp::GvcpCommand>(0x1234), payload, sizeof(payload));
		PTF_ASSERT_EQUAL(requestLayer.getCommand(), pcpp::GvcpCommand::Unknown, enumclass);

		pcpp::GvcpAcknowledgeLayer ackLayer(static_cast<pcpp::GvcpResponseStatus>(0x1234),
		                                    static_cast<pcpp::GvcpCommand>(0x4321));
		PTF_ASSERT_EQUAL(ackLayer.getStatus(), pcpp::GvcpResponseStatus::Unknown, enumclass);
		PTF_ASSERT_EQUAL(ackLayer.getCommand(), pcpp::GvcpCommand::Unknown, enumclass);
	}

	PTF_ASSERT_FALSE(pcpp::GvcpRequestLayer::isDataValid(nullptr, 8));
	PTF_ASSERT_FALSE(pcpp::GvcpAcknowledgeLayer::isDataValid(nullptr, 8));
	PTF_ASSERT_NULL(pcpp::GvcpLayer::parseGvcpLayer(nullptr, 8, nullptr, nullptr));
}  // GvcpMalformedParsingTest

PTF_TEST_CASE(GvcpLayerCreationTest)
{
	// Discovery command
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_discovery_cmd.dat");
		pcpp::Packet realPacket(rawPacket1.get());
		auto* realLayer = realPacket.getLayerOfType<pcpp::GvcpDiscoveryRequestLayer>();
		PTF_ASSERT_NOT_NULL(realLayer);

		pcpp::GvcpDiscoveryRequestLayer newLayer(0x11, 19942);
		PTF_ASSERT_EQUAL(newLayer.getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(newLayer.getDataLen(), realLayer->getDataLen());
		PTF_ASSERT_BUF_COMPARE(newLayer.getData(), realLayer->getData(), realLayer->getDataLen());
	}

	// Discovery acknowledge
	{
		pcpp::GvcpDiscoveryAcknowledgeLayer newLayer(pcpp::GvcpResponseStatus::Success, 1);
		PTF_ASSERT_EQUAL(newLayer.getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(newLayer.getCommand(), pcpp::GvcpCommand::DiscoveredAck, enumclass);
		PTF_ASSERT_EQUAL(newLayer.getDataLen(), 256);
		PTF_ASSERT_EQUAL(newLayer.getDataSize(), 248);

		newLayer.setVersion(2, 1);
		newLayer.setMacAddress(pcpp::MacAddress("00:04:4b:ea:b0:b4"));
		newLayer.setIpAddress(pcpp::IPv4Address("172.28.60.100"));
		newLayer.setSubnetMask(pcpp::IPv4Address("255.255.255.0"));
		newLayer.setGatewayIpAddress(pcpp::IPv4Address("172.28.60.1"));
		newLayer.setManufacturerName("Vendor01");
		newLayer.setModelName("ABCDE 3D Scanner (TW)");
		newLayer.setDeviceVersion("1.2.3");
		newLayer.setManufacturerSpecificInformation("info");
		newLayer.setSerialNumber("XXX-005");
		// longer than the field, should be truncated to 15 characters
		newLayer.setUserDefinedName("0123456789abcdefgh");

		PTF_ASSERT_EQUAL(newLayer.getVersion().first, 2);
		PTF_ASSERT_EQUAL(newLayer.getVersion().second, 1);
		PTF_ASSERT_EQUAL(newLayer.getMacAddress(), pcpp::MacAddress("00:04:4b:ea:b0:b4"));
		PTF_ASSERT_EQUAL(newLayer.getIpAddress(), pcpp::IPv4Address("172.28.60.100"));
		PTF_ASSERT_EQUAL(newLayer.getSubnetMask(), pcpp::IPv4Address("255.255.255.0"));
		PTF_ASSERT_EQUAL(newLayer.getGatewayIpAddress(), pcpp::IPv4Address("172.28.60.1"));
		PTF_ASSERT_EQUAL(newLayer.getManufacturerName(), "Vendor01");
		PTF_ASSERT_EQUAL(newLayer.getModelName(), "ABCDE 3D Scanner (TW)");
		PTF_ASSERT_EQUAL(newLayer.getDeviceVersion(), "1.2.3");
		PTF_ASSERT_EQUAL(newLayer.getManufacturerSpecificInformation(), "info");
		PTF_ASSERT_EQUAL(newLayer.getSerialNumber(), "XXX-005");
		PTF_ASSERT_EQUAL(newLayer.getUserDefinedName(), "0123456789abcde");
	}

	// Force IP command, as a part of a full packet
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_forceip_cmd.dat");
		pcpp::Packet realPacket(rawPacket1.get());

		pcpp::EthLayer ethLayer(*realPacket.getLayerOfType<pcpp::EthLayer>());
		pcpp::IPv4Layer ipLayer(*realPacket.getLayerOfType<pcpp::IPv4Layer>());
		pcpp::UdpLayer udpLayer(*realPacket.getLayerOfType<pcpp::UdpLayer>());
		pcpp::GvcpForceIpRequestLayer newLayer(pcpp::MacAddress("8c:e9:b4:01:63:b2"), pcpp::IPv4Address("192.168.5.1"),
		                                       pcpp::IPv4Address("255.255.0.0"), pcpp::IPv4Address("0.0.0.0"), 0x01,
		                                       8787);

		pcpp::Packet newPacket;
		PTF_ASSERT_TRUE(newPacket.addLayer(&ethLayer));
		PTF_ASSERT_TRUE(newPacket.addLayer(&ipLayer));
		PTF_ASSERT_TRUE(newPacket.addLayer(&udpLayer));
		PTF_ASSERT_TRUE(newPacket.addLayer(&newLayer));

		PTF_ASSERT_EQUAL(newPacket.getRawPacket()->getRawDataLen(), realPacket.getRawPacket()->getRawDataLen());
		PTF_ASSERT_BUF_COMPARE(newPacket.getRawPacket()->getRawData(), realPacket.getRawPacket()->getRawData(),
		                       realPacket.getRawPacket()->getRawDataLen());
	}

	// Force IP acknowledge
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_forceip_ack.dat");
		pcpp::Packet realPacket(rawPacket1.get());
		auto* realLayer = realPacket.getLayerOfType<pcpp::GvcpForceIpAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(realLayer);

		pcpp::GvcpForceIpAcknowledgeLayer newLayer(pcpp::GvcpResponseStatus::Success, 8787);
		PTF_ASSERT_EQUAL(newLayer.getDataLen(), realLayer->getDataLen());
		PTF_ASSERT_BUF_COMPARE(newLayer.getData(), realLayer->getData(), realLayer->getDataLen());
	}

	// Generic request and acknowledge with data
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_readreg_ack.dat");
		pcpp::Packet realPacket(rawPacket1.get());
		auto* realLayer = realPacket.getLayerOfType<pcpp::GvcpAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(realLayer);

		uint8_t payload[] = { 0x80, 0x00, 0x00, 0x01 };
		pcpp::GvcpAcknowledgeLayer newAckLayer(pcpp::GvcpResponseStatus::Success, pcpp::GvcpCommand::ReadRegAck,
		                                       payload, sizeof(payload), 0x1fee);
		PTF_ASSERT_EQUAL(newAckLayer.getDataLen(), realLayer->getDataLen());
		PTF_ASSERT_BUF_COMPARE(newAckLayer.getData(), realLayer->getData(), realLayer->getDataLen());

		pcpp::GvcpRequestLayer newRequestLayer(pcpp::GvcpCommand::ReadRegCmd, payload, sizeof(payload), 0x01, 2);
		PTF_ASSERT_EQUAL(newRequestLayer.getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(newRequestLayer.getCommand(), pcpp::GvcpCommand::ReadRegCmd, enumclass);
		PTF_ASSERT_EQUAL(newRequestLayer.getFlag(), 0x01);
		PTF_ASSERT_EQUAL(newRequestLayer.getRequestId(), 2);
		PTF_ASSERT_EQUAL(newRequestLayer.getDataSize(), sizeof(payload));
		PTF_ASSERT_EQUAL(newRequestLayer.getPayloadDataLen(), sizeof(payload));
		PTF_ASSERT_BUF_COMPARE(newRequestLayer.getPayloadData(), payload, sizeof(payload));
	}
}  // GvcpLayerCreationTest

PTF_TEST_CASE(GvcpLayerEditTest)
{
	// Request
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_forceip_cmd.dat");
		pcpp::Packet packet(rawPacket1.get());
		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpForceIpRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);

		gvcpLayer->setFlag(0x00);
		gvcpLayer->setRequestId(1234);
		gvcpLayer->setMacAddress(pcpp::MacAddress("00:11:22:33:44:55"));
		gvcpLayer->setIpAddress(pcpp::IPv4Address("10.0.0.2"));
		gvcpLayer->setSubnetMask(pcpp::IPv4Address("255.0.0.0"));
		gvcpLayer->setGatewayIpAddress(pcpp::IPv4Address("10.0.0.1"));

		PTF_ASSERT_EQUAL(gvcpLayer->getFlag(), 0x00);
		PTF_ASSERT_FALSE(gvcpLayer->hasAcknowledgeFlag());
		PTF_ASSERT_EQUAL(gvcpLayer->getRequestId(), 1234);
		PTF_ASSERT_EQUAL(gvcpLayer->getMacAddress(), pcpp::MacAddress("00:11:22:33:44:55"));
		PTF_ASSERT_EQUAL(gvcpLayer->getIpAddress(), pcpp::IPv4Address("10.0.0.2"));
		PTF_ASSERT_EQUAL(gvcpLayer->getSubnetMask(), pcpp::IPv4Address("255.0.0.0"));
		PTF_ASSERT_EQUAL(gvcpLayer->getGatewayIpAddress(), pcpp::IPv4Address("10.0.0.1"));
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::ForceIpCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 56);
	}

	// The data size field is calculated according to the size of the message data
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_forceip_cmd_short.dat");
		pcpp::Packet packet(rawPacket1.get());
		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		gvcpLayer->getData()[5] = 0x38;  // data size which doesn't match the message data
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 56);

		packet.computeCalculateFields();
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 8);
	}

	// Acknowledge
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_discovery_ack.dat");
		pcpp::Packet packet(rawPacket1.get());
		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpDiscoveryAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);

		gvcpLayer->setStatus(pcpp::GvcpResponseStatus::Busy);
		gvcpLayer->setAckId(4321);
		gvcpLayer->setModelName("New Model");

		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpResponseStatus::Busy, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 4321);
		PTF_ASSERT_EQUAL(gvcpLayer->getModelName(), "New Model");
		// the rest of the fields aren't affected
		PTF_ASSERT_EQUAL(gvcpLayer->getManufacturerName(), "Vendor01");
		PTF_ASSERT_EQUAL(gvcpLayer->getSerialNumber(), "XXX-005");
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpCommand::DiscoveredAck, enumclass);
	}
}  // GvcpLayerEditTest
