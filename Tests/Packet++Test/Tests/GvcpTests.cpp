#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EthLayer.h"
#include "GeneralUtils.h"
#include "GvcpLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "PacketTrailerLayer.h"
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
		PTF_ASSERT_EQUAL(std::string(pcpp::protocolTypeToString(pcpp::GVCP)), "GVCP");

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpDiscoveryRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(gvcpLayer->getOsiModelLayer(), pcpp::OsiModelApplicationLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getFlag(), 0x11);  // allow broadcast, acknowledge required
		PTF_ASSERT_TRUE(gvcpLayer->hasAcknowledgeFlag());
		PTF_ASSERT_TRUE(gvcpLayer->hasAllowBroadcastAckFlag());
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::DiscoveredCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getRequestId(), 19942);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 0);
		PTF_ASSERT_EQUAL(gvcpLayer->getHeaderLen(), 8);
		PTF_ASSERT_NULL(gvcpLayer->getNextLayer());
		PTF_ASSERT_EQUAL(gvcpLayer->toString(), "GVCP Request Layer, Command: DiscoveredCmd, Request ID: 19942");
	}

	// Discovery acknowledge
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_discovery_ack.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpDiscoveryAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpLayer::GvcpResponseStatus::Success, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::DiscoveredAck, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 1);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 248);
		PTF_ASSERT_EQUAL(gvcpLayer->getHeaderLen(), 256);
		PTF_ASSERT_NULL(gvcpLayer->getNextLayer());

		PTF_ASSERT_EQUAL(gvcpLayer->getMacAddress(), pcpp::MacAddress("00:04:4b:ea:b0:b4"));
		PTF_ASSERT_EQUAL(gvcpLayer->getIpAddress(), pcpp::IPv4Address("172.28.60.100"));
		PTF_ASSERT_EQUAL(gvcpLayer->getManufacturerName(), "Vendor01");
		PTF_ASSERT_EQUAL(gvcpLayer->getModelName(), "ABCDE 3D Scanner (TW)");
		PTF_ASSERT_EQUAL(gvcpLayer->getSerialNumber(), "XXX-005");
		PTF_ASSERT_EQUAL(gvcpLayer->toString(),
		                 "GVCP Acknowledge Layer, Command: DiscoveredAck, Acknowledge ID: 1, Status: Success");
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
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::ForceIpCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getRequestId(), 8787);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 56);
		PTF_ASSERT_EQUAL(gvcpLayer->getHeaderLen(), 64);
		PTF_ASSERT_NULL(gvcpLayer->getNextLayer());

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
		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpLayer::GvcpResponseStatus::Success, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::ForceIpAck, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 8787);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 0);
		PTF_ASSERT_EQUAL(gvcpLayer->getHeaderLen(), 8);
		PTF_ASSERT_NULL(packet.getLayerOfType<pcpp::PayloadLayer>());
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
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::ReadRegCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getRequestId(), 35824);
		PTF_ASSERT_EQUAL(gvcpLayer->getHeaderLen(), 8);

		auto* payloadLayer = packet.getLayerOfType<pcpp::PayloadLayer>();
		PTF_ASSERT_NOT_NULL(payloadLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getNextLayer(), payloadLayer, ptr);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), payloadLayer->getPayloadLen());
		PTF_ASSERT_EQUAL(pcpp::byteArrayToHexString(payloadLayer->getPayload(), 4), "00000000");
	}

	// Read register acknowledge
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_readreg_ack.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpLayer::GvcpResponseStatus::Success, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::ReadRegAck, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 0x1fee);

		auto* payloadLayer = packet.getLayerOfType<pcpp::PayloadLayer>();
		PTF_ASSERT_NOT_NULL(payloadLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), payloadLayer->getPayloadLen());
		PTF_ASSERT_EQUAL(pcpp::byteArrayToHexString(payloadLayer->getPayload(), 4), "80000001");
	}

	// Write register command
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_writereg_cmd.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getFlag(), 0x01);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::WriteRegCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getRequestId(), 8788);

		auto* payloadLayer = packet.getLayerOfType<pcpp::PayloadLayer>();
		PTF_ASSERT_NOT_NULL(payloadLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), payloadLayer->getPayloadLen());
		PTF_ASSERT_EQUAL(pcpp::byteArrayToHexString(payloadLayer->getPayload(), payloadLayer->getPayloadLen()),
		                 "00000a00000000020000064cc0a805010000065cffff00000000001400000005");
	}

	// Write register acknowledge with an error status
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_writereg_ack.dat");
		pcpp::Packet packet(rawPacket1.get());
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::GVCP));

		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpAcknowledgeLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpLayer::GvcpResponseStatus::AccessDenied, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::WriteRegAck, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 8788);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 0);
		PTF_ASSERT_NULL(packet.getLayerOfType<pcpp::PayloadLayer>());
		PTF_ASSERT_EQUAL(gvcpLayer->toString(),
		                 "GVCP Acknowledge Layer, Command: WriteRegAck, Acknowledge ID: 8788, Status: AccessDenied");
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
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::ForceIpCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getHeaderLen(), 8);

		auto* payloadLayer = packet.getLayerOfType<pcpp::PayloadLayer>();
		PTF_ASSERT_NOT_NULL(payloadLayer);
		PTF_ASSERT_EQUAL(payloadLayer->getPayloadLen(), 8);
	}

	// Unknown command and status values
	{
		pcpp::GvcpRequestLayer requestLayer(static_cast<pcpp::GvcpLayer::GvcpCommand>(0x1234));
		PTF_ASSERT_EQUAL(requestLayer.getCommand(), pcpp::GvcpLayer::GvcpCommand::Unknown, enumclass);

		pcpp::GvcpAcknowledgeLayer ackLayer(static_cast<pcpp::GvcpLayer::GvcpResponseStatus>(0x1234),
		                                    static_cast<pcpp::GvcpLayer::GvcpCommand>(0x4321));
		PTF_ASSERT_EQUAL(ackLayer.getStatus(), pcpp::GvcpLayer::GvcpResponseStatus::Unknown, enumclass);
		PTF_ASSERT_EQUAL(ackLayer.getCommand(), pcpp::GvcpLayer::GvcpCommand::Unknown, enumclass);
		PTF_ASSERT_EQUAL(ackLayer.toString(),
		                 "GVCP Acknowledge Layer, Command: Unknown, Acknowledge ID: 0, Status: Unknown");
	}

	// A request can't be created with an acknowledge value, and an acknowledge can't be created with a command value
	{
		PTF_ASSERT_RAISES(pcpp::GvcpRequestLayer{ pcpp::GvcpLayer::GvcpCommand::ReadRegAck }, std::invalid_argument,
		                  "A GVCP request can't be created with an acknowledge value");
		PTF_ASSERT_RAISES(pcpp::GvcpAcknowledgeLayer(pcpp::GvcpLayer::GvcpResponseStatus::Success,
		                                             pcpp::GvcpLayer::GvcpCommand::ReadRegCmd),
		                  std::invalid_argument, "A GVCP acknowledge can't be created with a command value");
	}

	PTF_ASSERT_FALSE(pcpp::GvcpDiscoveryAcknowledgeLayer::isDataValid(nullptr, 256));
	PTF_ASSERT_FALSE(pcpp::GvcpForceIpRequestLayer::isDataValid(nullptr, 64));
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

		pcpp::GvcpDiscoveryRequestLayer newLayer(true, true, 19942);
		PTF_ASSERT_EQUAL(newLayer.getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(newLayer.getDataLen(), realLayer->getDataLen());
		PTF_ASSERT_BUF_COMPARE(newLayer.getData(), realLayer->getData(), realLayer->getDataLen());

		newLayer.setAllowBroadcastAckFlag(false);
		PTF_ASSERT_FALSE(newLayer.hasAllowBroadcastAckFlag());
		PTF_ASSERT_TRUE(newLayer.hasAcknowledgeFlag());
		PTF_ASSERT_EQUAL(newLayer.getFlag(), 0x01);
		newLayer.setAllowBroadcastAckFlag(true);
		PTF_ASSERT_EQUAL(newLayer.getFlag(), 0x11);

		pcpp::GvcpDiscoveryRequestLayer defaultLayer;
		PTF_ASSERT_EQUAL(defaultLayer.getFlag(), 0x01);
		PTF_ASSERT_EQUAL(defaultLayer.getRequestId(), 1);
	}

	// Discovery acknowledge
	{
		pcpp::GvcpDiscoveryAcknowledgeLayer newLayer(pcpp::GvcpLayer::GvcpResponseStatus::Success, 1);
		PTF_ASSERT_EQUAL(newLayer.getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(newLayer.getCommand(), pcpp::GvcpLayer::GvcpCommand::DiscoveredAck, enumclass);
		PTF_ASSERT_EQUAL(newLayer.getDataLen(), 256);
		PTF_ASSERT_EQUAL(newLayer.getDataSize(), 248);

		newLayer.setVersion({ 2, 1 });
		newLayer.setMacAddress(pcpp::MacAddress("00:04:4b:ea:b0:b4"));
		newLayer.setIpAddress(pcpp::IPv4Address("172.28.60.100"));
		newLayer.setSubnetMask(pcpp::IPv4Address("255.255.255.0"));
		newLayer.setGatewayIpAddress(pcpp::IPv4Address("172.28.60.1"));
		newLayer.setManufacturerName("Vendor01");
		newLayer.setModelName("ABCDE 3D Scanner (TW)");
		newLayer.setDeviceVersion("1.2.3");
		newLayer.setManufacturerSpecificInformation("info");
		newLayer.setSerialNumber("XXX-005");
		// the name is longer than the field, so the setter truncates it to 15 characters
		newLayer.setUserDefinedName("0123456789abcdefgh");

		PTF_ASSERT_EQUAL(newLayer.getVersion().major, 2);
		PTF_ASSERT_EQUAL(newLayer.getVersion().minor, 1);
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

		pcpp::GvcpForceIpAcknowledgeLayer newLayer(pcpp::GvcpLayer::GvcpResponseStatus::Success, 8787);
		PTF_ASSERT_EQUAL(newLayer.getDataLen(), realLayer->getDataLen());
		PTF_ASSERT_BUF_COMPARE(newLayer.getData(), realLayer->getData(), realLayer->getDataLen());
	}

	// Generic acknowledge followed by a payload layer, as a part of a full packet
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_readreg_ack.dat");
		pcpp::Packet realPacket(rawPacket1.get());

		pcpp::EthLayer ethLayer(*realPacket.getLayerOfType<pcpp::EthLayer>());
		pcpp::IPv4Layer ipLayer(*realPacket.getLayerOfType<pcpp::IPv4Layer>());
		pcpp::UdpLayer udpLayer(*realPacket.getLayerOfType<pcpp::UdpLayer>());
		pcpp::GvcpAcknowledgeLayer newAckLayer(pcpp::GvcpLayer::GvcpResponseStatus::Success,
		                                       pcpp::GvcpLayer::GvcpCommand::ReadRegAck, 0x1fee);
		PTF_ASSERT_EQUAL(newAckLayer.getDataLen(), 8);
		PTF_ASSERT_EQUAL(newAckLayer.getDataSize(), 0);

		uint8_t payload[] = { 0x80, 0x00, 0x00, 0x01 };
		pcpp::PayloadLayer payloadLayer(payload, sizeof(payload));

		pcpp::Packet newPacket;
		PTF_ASSERT_TRUE(newPacket.addLayer(&ethLayer));
		PTF_ASSERT_TRUE(newPacket.addLayer(&ipLayer));
		PTF_ASSERT_TRUE(newPacket.addLayer(&udpLayer));
		PTF_ASSERT_TRUE(newPacket.addLayer(&newAckLayer));
		PTF_ASSERT_TRUE(newPacket.addLayer(&payloadLayer));
		newAckLayer.computeCalculateFields();

		PTF_ASSERT_EQUAL(newAckLayer.getDataSize(), sizeof(payload));

		// the real packet ends with an Ethernet padding which the new packet doesn't have
		auto* trailerLayer = realPacket.getLayerOfType<pcpp::PacketTrailerLayer>();
		PTF_ASSERT_NOT_NULL(trailerLayer);
		const size_t expectedLen = realPacket.getRawPacket()->getRawDataLen() - trailerLayer->getDataLen();
		PTF_ASSERT_EQUAL(newPacket.getRawPacket()->getRawDataLen(), expectedLen);
		PTF_ASSERT_BUF_COMPARE(newPacket.getRawPacket()->getRawData(), realPacket.getRawPacket()->getRawData(),
		                       expectedLen);
	}

	// Generic request
	{
		pcpp::GvcpRequestLayer newRequestLayer(pcpp::GvcpLayer::GvcpCommand::ReadRegCmd, 0x01, 2);
		PTF_ASSERT_EQUAL(newRequestLayer.getProtocol(), pcpp::GVCP);
		PTF_ASSERT_EQUAL(newRequestLayer.getCommand(), pcpp::GvcpLayer::GvcpCommand::ReadRegCmd, enumclass);
		PTF_ASSERT_EQUAL(newRequestLayer.getFlag(), 0x01);
		PTF_ASSERT_EQUAL(newRequestLayer.getRequestId(), 2);
		PTF_ASSERT_EQUAL(newRequestLayer.getDataSize(), 0);
		PTF_ASSERT_EQUAL(newRequestLayer.getDataLen(), 8);
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
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::ForceIpCmd, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getDataSize(), 56);
	}

	// The data size field is calculated from the size of the data after the GVCP header
	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/gvcp_forceip_cmd_short.dat");
		pcpp::Packet packet(rawPacket1.get());
		auto* gvcpLayer = packet.getLayerOfType<pcpp::GvcpRequestLayer>();
		PTF_ASSERT_NOT_NULL(gvcpLayer);
		gvcpLayer->getData()[5] = 0x38;  // a data size which doesn't match the data after the header
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

		gvcpLayer->setStatus(pcpp::GvcpLayer::GvcpResponseStatus::Busy);
		gvcpLayer->setAckId(4321);
		gvcpLayer->setModelName("New Model");

		PTF_ASSERT_EQUAL(gvcpLayer->getStatus(), pcpp::GvcpLayer::GvcpResponseStatus::Busy, enumclass);
		PTF_ASSERT_EQUAL(gvcpLayer->getAckId(), 4321);
		PTF_ASSERT_EQUAL(gvcpLayer->getModelName(), "New Model");
		// the rest of the fields aren't affected
		PTF_ASSERT_EQUAL(gvcpLayer->getManufacturerName(), "Vendor01");
		PTF_ASSERT_EQUAL(gvcpLayer->getSerialNumber(), "XXX-005");
		PTF_ASSERT_EQUAL(gvcpLayer->getCommand(), pcpp::GvcpLayer::GvcpCommand::DiscoveredAck, enumclass);
	}
}  // GvcpLayerEditTest
