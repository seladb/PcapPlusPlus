#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"
#include "PacketUtils.h"
#include "DeprecationUtils.h"
#include <memory>
#include <array>
#include "DoIpLayer.h"
#include "GeneralUtils.h"

// RoutingActivationRequest
PTF_TEST_CASE(DoIpRoutingActivationRequestPacketParsing)
{
	// Dissect Routing Activation Request message
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpRoutingActivationRequestPacket.dat");

	pcpp::Packet RoutingActivationRequest(&rawPacket1);
	PTF_ASSERT_TRUE(RoutingActivationRequest.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(RoutingActivationRequest.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(RoutingActivationRequest.isPacketOfType(pcpp::DOIP));

	pcpp::TcpLayer* tcpLayer = RoutingActivationRequest.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = RoutingActivationRequest.getLayerOfType<pcpp::DoIpRoutingActivationRequest>();

	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Routing activation request");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 11);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Routing activation request (0x0005)");
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x0e80);
	PTF_ASSERT_EQUAL(doipLayer->getActivationType(), pcpp::DoIpActivationTypes::DEFAULT, enumclass);
	std::array<uint8_t, 4> isoField = { 0x0, 0x0, 0x0, 0x0 };
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getReservedIso(), isoField);
	PTF_ASSERT_TRUE(doipLayer->hasReservedOem());
	std::array<uint8_t, 4> oemField = { 0x0, 0x0, 0x0, 0x0 };
	PTF_ASSERT_BUF_COMPARE(doipLayer->getReservedOem().data(), oemField.data(), 4);

	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "Source Address: 0xe80\nActivation type: Default (0x0)\nReserved by ISO: 00000000\nReserved by OEM: 00000000\n");
}

PTF_TEST_CASE(DoIpRoutingActivationRequestPacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer((uint16_t)13400, (uint16_t)13400);

	tcpLayer.getTcpHeader()->windowSize = 64240;
	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x0, 0x5, 0x0, 0x0,  0x0,  0xb,  0xe, 0x80,
		                      0x0, 0x1,  0x2, 0x3, 0x4, 0x05, 0x05, 0x05, 0x05 };
	std::array<uint8_t, 4> isoReserved{ 0x1, 0x2, 0x3, 0x4 };
	std::array<uint8_t, 4> oemField{ 0x5, 0x5, 0x5, 0x5 };

	pcpp::DoIpRoutingActivationRequest doipLayer(0x00, pcpp::DoIpActivationTypes::WWH_OBD);

	doipLayer.setSourceAddress(0x0e80);
	doipLayer.setActivationType(pcpp::DoIpActivationTypes::DEFAULT);
	doipLayer.setReservedIso(isoReserved);
	doipLayer.setReservedOem(oemField);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer));
	doIpPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 73);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (73 - 19), bytes, 19);
	// check for setting invalid protocol version, will be applicable for all derived classes
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	doipLayer.setProtocolVersion(0x55);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::UnknownVersion, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersionAsStr(), "Unknown Protocol Version");
	doipLayer.setProtocolVersion(pcpp::DoIpProtocolVersion::Version02Iso2012);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer.getPayloadType(), pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getPayloadTypeAsStr(), "Routing activation request");
	PTF_ASSERT_EQUAL(doipLayer.getPayloadLength(), 11);
	PTF_ASSERT_EQUAL(doipLayer.toString(), "DoIP Layer, Routing activation request (0x0005)");

	PTF_ASSERT_EQUAL(doipLayer.getSourceAddress(), 0x0e80);
	PTF_ASSERT_EQUAL(doipLayer.getActivationType(), pcpp::DoIpActivationTypes::DEFAULT, enumclass);

	PTF_ASSERT_TRUE(doipLayer.hasReservedOem());
	PTF_ASSERT_BUF_COMPARE(doipLayer.getReservedOem().data(), oemField.data(), 4);

	doipLayer.clearReservedOem();

	PTF_ASSERT_FALSE(doipLayer.hasReservedOem());
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 73 - 4);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (73 - 4) - 15, bytes, 15);
	PTF_ASSERT_VECTORS_EQUAL(doipLayer.getReservedIso(), isoReserved);
	PTF_ASSERT_FALSE(doipLayer.hasReservedOem());
	PTF_ASSERT_EQUAL(doipLayer.getSummary(),
	                 "Source Address: 0xe80\nActivation type: Default (0x0)\nReserved by ISO: 01020304\n");
	doipLayer.setReservedOem(oemField);
	PTF_ASSERT_TRUE(doipLayer.hasReservedOem());
	PTF_ASSERT_EQUAL(
	    doipLayer.getSummary(),
	    "Source Address: 0xe80\nActivation type: Default (0x0)\nReserved by ISO: 01020304\nReserved by OEM: 05050505\n");
}
// RoutingActivationResponse
PTF_TEST_CASE(DoIpRoutingActivationResponsePacketParsing)
{
	// Dissect Routing Activation Response message
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpRoutingActivationResponsePacket.dat");

	pcpp::Packet RoutingActivationResponse(&rawPacket1);
	PTF_ASSERT_TRUE(RoutingActivationResponse.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(RoutingActivationResponse.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(RoutingActivationResponse.isPacketOfType(pcpp::DOIP));

	pcpp::TcpLayer* tcpLayer = RoutingActivationResponse.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getDstPort(), 53850);
	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_UDP_PORT);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->headerChecksum, be16toh(0xa0a5));

	auto* doipLayer = RoutingActivationResponse.getLayerOfType<pcpp::DoIpRoutingActivationResponse>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Routing activation response");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 9);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Routing activation response (0x0006)");
	PTF_ASSERT_EQUAL(doipLayer->getLogicalAddressExternalTester(), 0x0e80);
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x4010);
	PTF_ASSERT_EQUAL(doipLayer->getResponseCode(), pcpp::DoIpRoutingResponseCodes::ROUTING_SUCCESSFULLY_ACTIVATED,
	                 enumclass);
	std::array<uint8_t, 4> resISO{};
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getReservedIso(), resISO);
	PTF_ASSERT_FALSE(doipLayer->hasReservedOem());
	try
	{
		doipLayer->getReservedOem();
	}
	catch (const std::runtime_error& e)
	{
		PTF_ASSERT_EQUAL(std::string(e.what()), "Reserved OEM field not present!");
	}
	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "Logical Address (Tester): 0xe80\nSource Address: 0x4010\nRouting activation response code: Routing successfully activated (0x10)\nReserved by ISO: 00000000\n");
}

PTF_TEST_CASE(DoIpRoutingActivationResponsePacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer((uint16_t)13400, (uint16_t)13400);

	tcpLayer.getTcpHeader()->windowSize = 64240;
	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2,  0xfd, 0x0, 0x6, 0x0, 0x0, 0x0, 0xd, 0xe, 0x80, 0x40,
		                      0x10, 0x10, 0x1, 0x2, 0x3, 0x4, 0x5, 0x5, 0x5, 0x5 };

	pcpp::DoIpRoutingActivationResponse doipLayer(0x0, 0x0, pcpp::DoIpRoutingResponseCodes::WRONG_SOURCE_ADDRESS);
	doipLayer.setLogicalAddressExternalTester(0x0e80);
	doipLayer.setSourceAddress(0x4010);
	doipLayer.setResponseCode(pcpp::DoIpRoutingResponseCodes::ROUTING_SUCCESSFULLY_ACTIVATED);
	doipLayer.setReservedIso({ 0x1, 0x2, 0x3, 0x4 });
	doipLayer.setReservedOem({ 0x5, 0x5, 0x5, 0x5 });

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 75);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (75 - 21), bytes, 21);

	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer.getPayloadType(), pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getPayloadTypeAsStr(), "Routing activation response");
	PTF_ASSERT_EQUAL(doipLayer.getPayloadLength(), 13);
	PTF_ASSERT_EQUAL(doipLayer.toString(), "DoIP Layer, Routing activation response (0x0006)")
	std::array<uint8_t, 4> resISO{ 0x1, 0x2, 0x3, 0x4 };
	std::array<uint8_t, 4> resOEM{ 0x5, 0x5, 0x5, 0x5 };
	PTF_ASSERT_VECTORS_EQUAL(doipLayer.getReservedIso(), resISO);
	PTF_ASSERT_TRUE(doipLayer.hasReservedOem());
	PTF_ASSERT_BUF_COMPARE(doipLayer.getReservedOem().data(), resOEM.data(), 4);
	PTF_ASSERT_EQUAL(
	    doipLayer.getSummary(),
	    "Logical Address (Tester): 0xe80\nSource Address: 0x4010\nRouting activation response code: Routing successfully activated (0x10)\nReserved by ISO: 01020304\nReserved by OEM: 05050505\n");
	doipLayer.clearReservedOem();
	PTF_ASSERT_FALSE(doipLayer.hasReservedOem());
	PTF_ASSERT_EQUAL(
	    doipLayer.getSummary(),
	    "Logical Address (Tester): 0xe80\nSource Address: 0x4010\nRouting activation response code: Routing successfully activated (0x10)\nReserved by ISO: 01020304\n");
}

// GenericHeaderNackPacket
PTF_TEST_CASE(DoIpGenericHeaderNackPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpGenericHeaderNackPacket.dat");

	pcpp::Packet GenericHeaderNack(&rawPacket1);
	PTF_ASSERT_TRUE(GenericHeaderNack.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(GenericHeaderNack.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(GenericHeaderNack.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = GenericHeaderNack.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = GenericHeaderNack.getLayerOfType<pcpp::DoIpGenericHeaderNack>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Generic DOIP header Nack");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Generic DOIP header Nack (0x0000)");
	PTF_ASSERT_EQUAL(doipLayer->getNackCode(), pcpp::DoIpGenericHeaderNackCodes::UNKNOWN_PAYLOAD_TYPE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Generic header nack code: Unknown payload type (0x1)\n");
}

// DoIpGenericHeaderNackPacketCreation
PTF_TEST_CASE(DoIpGenericHeaderNackPacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 };
	pcpp::DoIpGenericHeaderNack doipLayer(pcpp::DoIpGenericHeaderNackCodes::UNKNOWN_PAYLOAD_TYPE);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 51);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (51 - 9), bytes, 9);

	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer.getPayloadType(), pcpp::DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getPayloadTypeAsStr(), "Generic DOIP header Nack");
	PTF_ASSERT_EQUAL(doipLayer.getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(doipLayer.toString(), "DoIP Layer, Generic DOIP header Nack (0x0000)");
	PTF_ASSERT_EQUAL(doipLayer.getNackCode(), pcpp::DoIpGenericHeaderNackCodes::UNKNOWN_PAYLOAD_TYPE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getSummary(), "Generic header nack code: Unknown payload type (0x1)\n");
}

// VehicleIdentificationWithEID
PTF_TEST_CASE(DoIpVehicleIdentificationRequestWEIDPacketParsing)
{
	// Dissect Vehicle identification Request with EID
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestWEIDPacket.dat");

	pcpp::Packet VehicleIdentificationRequestEID(&rawPacket1);
	PTF_ASSERT_TRUE(VehicleIdentificationRequestEID.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(VehicleIdentificationRequestEID.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(VehicleIdentificationRequestEID.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = VehicleIdentificationRequestEID.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);

	auto* doipLayer = VehicleIdentificationRequestEID.getLayerOfType<pcpp::DoIpVehicleIdentificationRequestWEID>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "EID: 4241554e4545\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID,
	                 enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request with EID");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x6);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Vehicle identification request with EID (0x0002)")
	std::array<uint8_t, 6> eid{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45 };
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getEID(), eid);

}  // VehicleIdentificationWithEIDacketParsing

// DoIpVehicleIdentificationRequestWEIDPacketCreation
PTF_TEST_CASE(DoIpVehicleIdentificationRequestWEIDPacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)65300, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x0, 0x2, 0x0, 0x0, 0x0, 0x6, 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45 };
	std::array<uint8_t, 6> eid{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45 };

	pcpp::DoIpVehicleIdentificationRequestWEID withEID(eid);
	withEID.setEID(eid);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&withEID));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 56);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (56 - 14), bytes, 14);

	PTF_ASSERT_EQUAL(withEID.getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(withEID.getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(withEID.getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID,
	                 enumclass);
	PTF_ASSERT_EQUAL(withEID.getPayloadTypeAsStr(), "Vehicle identification request with EID");
	PTF_ASSERT_EQUAL(withEID.getPayloadLength(), 6);
	PTF_ASSERT_EQUAL(withEID.toString(), "DoIP Layer, Vehicle identification request with EID (0x0002)");
	PTF_ASSERT_VECTORS_EQUAL(withEID.getEID(), eid);
	PTF_ASSERT_EQUAL(withEID.getSummary(), "EID: 4241554e4545\n");
}  // DoIpVehicleIdentificationRequestWEIDPacketCreation

// DoIpVehicleIdentificationRequestWVINPacketParsing
PTF_TEST_CASE(DoIpVehicleIdentificationRequestWVINPacketParsing)
{
	// Dissect Vehicle identification Request with VIN
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestWVINPacket.dat");

	pcpp::Packet VehicleIdentificationRequestVIN(&rawPacket1);
	PTF_ASSERT_TRUE(VehicleIdentificationRequestVIN.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(VehicleIdentificationRequestVIN.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(VehicleIdentificationRequestVIN.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = VehicleIdentificationRequestVIN.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = VehicleIdentificationRequestVIN.getLayerOfType<pcpp::DoIpVehicleIdentificationRequestWVIN>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN,
	                 enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request with VIN");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x11);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Vehicle identification request with VIN (0x0003)");
	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "VIN: BAUNEE4MZ17042403\n");
	std::array<uint8_t, 17> vin{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a,
		                         0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };

	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getVIN(), vin);

}  // DoIpVehicleIdentificationRequestVINPacketParsing

// DoIpVehicleIdentificationRequestWVINPacketCreation
PTF_TEST_CASE(DoIpVehicleIdentificationRequestWVINPacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)65300, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2,  0xfd, 0x0,  0x3,  0x0,  0x0,  0x0,  0x11, 0x42, 0x41, 0x55, 0x4e, 0x45,
		                      0x45, 0x34, 0x4d, 0x5a, 0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };
	std::array<uint8_t, 17> vin{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a,
		                         0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };

	pcpp::DoIpVehicleIdentificationRequestWVIN withVin(vin);
	withVin.setVIN(vin);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&withVin));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 67);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (67 - 25), bytes, 25);

	PTF_ASSERT_EQUAL(withVin.getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(withVin.getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(withVin.getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN,
	                 enumclass);
	PTF_ASSERT_EQUAL(withVin.getPayloadTypeAsStr(), "Vehicle identification request with VIN");
	PTF_ASSERT_EQUAL(withVin.getPayloadLength(), 17);
	PTF_ASSERT_EQUAL(withVin.toString(), "DoIP Layer, Vehicle identification request with VIN (0x0003)");
	PTF_ASSERT_EQUAL(withVin.getSummary(), "VIN: BAUNEE4MZ17042403\n");
	PTF_ASSERT_VECTORS_EQUAL(withVin.getVIN(), vin);
}  // DoIpVehicleIdentificationRequestVINPacketCreation

// DoIpVehicleAnnouncementPacketParsing
PTF_TEST_CASE(DoIpVehicleAnnouncementPacketParsing)
{
	// Dissect Vehicle Announcement message
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleAnnouncementPacket.dat");

	std::array<uint8_t, 6> eid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, 6> gid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, 17> vin{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a,
		                         0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };

	pcpp::Packet VehicleAnnouncement(&rawPacket1);
	PTF_ASSERT_TRUE(VehicleAnnouncement.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(VehicleAnnouncement.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = VehicleAnnouncement.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	// DOIP fields for vehicle identification request
	auto* doipLayer = VehicleAnnouncement.getLayerOfType<pcpp::DoIpVehicleAnnouncement>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "VIN: BAUNEE4MZ17042403\nLogical address: 0x4010\nEID: 001a37bfee74\nGID: 001a37bfee74\nFurther action required: No further action required (0x0)\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(),
	                 "Vehicle announcement message / vehicle identification response message");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 32);
	PTF_ASSERT_EQUAL(doipLayer->toString(),
	                 "DoIP Layer, Vehicle announcement message / vehicle identification response message (0x0004)");
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getVIN(), vin);
	PTF_ASSERT_EQUAL(doipLayer->getLogicalAddress(), 0x4010);
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getEID(), eid);
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getGID(), gid);
	PTF_ASSERT_FALSE(doipLayer->hasSyncStatus());
	try
	{
		doipLayer->getSyncStatus();
	}
	catch (const std::runtime_error& e)
	{
		PTF_ASSERT_EQUAL(std::string(e.what()), "Sync status field not present!");
	}
}  // DoIpVehicleAnnouncementPacketParsing

// DoIpVehicleAnnouncementPacketCreation
PTF_TEST_CASE(DoIpVehicleAnnouncementPacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2,  0xfd, 0x0,  0x4,  0x0,  0x0,  0x0,  0x21, 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45,
		                      0x34, 0x4d, 0x5a, 0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33, 0x40, 0x10, 0x0,
		                      0x1a, 0x37, 0xbf, 0xee, 0x74, 0x0,  0x1a, 0x37, 0xbf, 0xee, 0x74, 0x0,  0x0 };
	std::array<uint8_t, 6> eid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, 6> gid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, 17> vin{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a,
		                         0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };

	pcpp::DoIpVehicleAnnouncement ann(vin, 0x4010, eid, gid, pcpp::DoIpActionCodes::NO_FURTHER_ACTION_REQUIRED);
	ann.setSyncStatus(pcpp::DoIpSyncStatus::VIN_AND_OR_GID_ARE_SINCHRONIZED);
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ann));
	doIpPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 83);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (83 - 41), bytes, 41);
	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpVehicleAnnouncement>();

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(),
	                 "Vehicle announcement message / vehicle identification response message");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 33);
	PTF_ASSERT_EQUAL(doipLayer->toString(),
	                 "DoIP Layer, Vehicle announcement message / vehicle identification response message (0x0004)");

	PTF_ASSERT_EQUAL(doipLayer->getLogicalAddress(), 0x4010);
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getEID(), eid);
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getGID(), gid);
	PTF_ASSERT_TRUE(doipLayer->hasSyncStatus());
	PTF_ASSERT_EQUAL(doipLayer->getSyncStatus(), pcpp::DoIpSyncStatus::VIN_AND_OR_GID_ARE_SINCHRONIZED, enumclass);
	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "VIN: BAUNEE4MZ17042403\nLogical address: 0x4010\nEID: 001a37bfee74\nGID: 001a37bfee74\nFurther action required: No further action required (0x0)\nVIN/GID sync status: VIN and/or GID are synchronized (0x0)\n");
	doipLayer->clearSyncStatus();
	PTF_ASSERT_FALSE(doipLayer->hasSyncStatus());
	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "VIN: BAUNEE4MZ17042403\nLogical address: 0x4010\nEID: 001a37bfee74\nGID: 001a37bfee74\nFurther action required: No further action required (0x0)\n");
}  // DoIpVehicleIdentificationRequestPacketParsing

// DoIpVehicleIdentificationRequestPacketParsing
PTF_TEST_CASE(DoIpVehicleIdentificationRequestPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestPacket.dat");

	pcpp::Packet vehicleIdentificationRequest(&rawPacket1);
	PTF_ASSERT_TRUE(vehicleIdentificationRequest.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(vehicleIdentificationRequest.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(vehicleIdentificationRequest.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = vehicleIdentificationRequest.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = vehicleIdentificationRequest.getLayerOfType<pcpp::DoIpVehicleIdentificationRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request");
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Vehicle identification request (0x0001)");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x0);

}  // DoIpVehicleIdentificationRequestPacketParsing

// DoIpVehicleIdentificationRequestPacketCreation
PTF_TEST_CASE(DoIpVehicleIdentificationRequestPacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));

	ipLayer.getIPv4Header()->ipId = htobe16(20370);
	ipLayer.getIPv4Header()->timeToLive = 128;
	pcpp::UdpLayer udpLayer((uint16_t)65300, (uint16_t)13400);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));

	unsigned char bytes[] = { 0x2, 0xfd, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0 };

	pcpp::DoIpVehicleIdentificationRequest req;
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&req));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), bytes, 8);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Vehicle identification request");
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DoIP Layer, Vehicle identification request (0x0001)");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 0x0);
}  // DoIpVehicleIdentificationRequestPacketCreation

// DoIpAliveCheckResponsePacketParsing
PTF_TEST_CASE(DoIpAliveCheckResponsePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpAliveCheckResponsePacket.dat");

	pcpp::Packet AliveCheckResponse(&rawPacket1);
	PTF_ASSERT_TRUE(AliveCheckResponse.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(AliveCheckResponse.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(AliveCheckResponse.isPacketOfType(pcpp::DOIP));

	auto* udpLayer = AliveCheckResponse.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = AliveCheckResponse.getLayerOfType<pcpp::DoIpAliveCheckResponse>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Source Address: 0x0\n");
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Alive check response");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 2);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Alive check response (0x0008)");
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x00);
}  // DoIpAliveCheckResponsePacketParsing

// DoIpAliveCheckResponsePacketCreation
PTF_TEST_CASE(DoIpAliveCheckResponsePacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x0, 0x8, 0x0, 0x0, 0x0, 0x2, 0x10, 0x20 };
	pcpp::DoIpAliveCheckResponse aliveCheckResp(0x1020);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&aliveCheckResp));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 52);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (52 - 10), bytes, 10);
	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpAliveCheckResponse>();

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Alive check response");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 2);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Alive check response (0x0008)");
	doipLayer->setSourceAddress(0x3040);
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x3040);
	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Source Address: 0x3040\n");
}  // DoIpAliveCheckResponsePacketCreation

// DoIpPowerModeResponsePacketParsing
PTF_TEST_CASE(DoIpPowerModeResponsePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpPowerModeResponsePacket.dat");

	pcpp::Packet PowerModeResponse(&rawPacket1);
	PTF_ASSERT_TRUE(PowerModeResponse.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(PowerModeResponse.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(PowerModeResponse.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = PowerModeResponse.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = PowerModeResponse.getLayerOfType<pcpp::DoIpDiagnosticPowerModeResponse>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Diagnostic power mode: not ready (0x0)\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic power mode response information");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic power mode response information (0x4004)");
	PTF_ASSERT_EQUAL(doipLayer->getPowerModeCode(), pcpp::DoIpDiagnosticPowerModeCodes::NOT_READY, enumclass);
}  // DoIpPowerModeResponsePacketParsing

// DoIpPowerModeResponsePacketCreation
PTF_TEST_CASE(DoIpPowerModeResponsePacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x40, 0x4, 0x0, 0x0, 0x0, 0x1, 0x1 };
	pcpp::DoIpDiagnosticPowerModeResponse data(pcpp::DoIpDiagnosticPowerModeCodes::READY);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&data));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 51);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (51 - 9), bytes, 9);
	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpDiagnosticPowerModeResponse>();

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic power mode response information");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic power mode response information (0x4004)");
	PTF_ASSERT_EQUAL(doipLayer->getPowerModeCode(), pcpp::DoIpDiagnosticPowerModeCodes::READY, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Diagnostic power mode: ready (0x1)\n");
	doipLayer->setPowerModeCode(pcpp::DoIpDiagnosticPowerModeCodes::NOT_SUPPORTED);
	PTF_ASSERT_EQUAL(doipLayer->getPowerModeCode(), pcpp::DoIpDiagnosticPowerModeCodes::NOT_SUPPORTED, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Diagnostic power mode: not supported (0x2)\n");
}  // DoIpPowerModeResponsePacketCreation

// DoIpEntityStatusResponsePacketParsing
PTF_TEST_CASE(DoIpEntityStatusResponsePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpEntityStatusResponsePacket.dat");

	pcpp::Packet EntityStatusResponse(&rawPacket1);
	PTF_ASSERT_TRUE(EntityStatusResponse.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(EntityStatusResponse.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(EntityStatusResponse.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = EntityStatusResponse.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = EntityStatusResponse.getLayerOfType<pcpp::DoIpEntityStatusResponse>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "Entity status: DoIP gateway (0x0)\nMax Concurrent Socket: 1\nCurrently Opened Socket: 0\nMax Data Size: 0x00000fff\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ENTITY_STATUS_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "DOIP entity status response");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 7);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, DOIP entity status response (0x4002)");
	PTF_ASSERT_EQUAL(doipLayer->getNodeType(), pcpp::DoIpEntityStatusResponseCode::GATEWAY, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getMaxConcurrentSockets(), 1);
	PTF_ASSERT_EQUAL(doipLayer->getCurrentlyOpenSockets(), 0);
	PTF_ASSERT_TRUE(doipLayer->hasMaxDataSize());
	const uint32_t maxDataSize = 0x000000fff;
	PTF_ASSERT_EQUAL(doipLayer->getMaxDataSize(), maxDataSize);
}  // DoIpEntityStatusResponsePacketParsing

// DoIpEntityStatusResponsePacketCreation
PTF_TEST_CASE(DoIpEntityStatusResponsePacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytesWithoutMaxDataSize[] = { 0x2, 0xfd, 0x40, 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x5, 0x2 };
	unsigned char bytes[] = { 0x2, 0xfd, 0x40, 0x2, 0x0, 0x0, 0x0, 0x7, 0x0, 0x5, 0x2, 0x11, 0x22, 0x33, 0x44 };
	pcpp::DoIpEntityStatusResponse data(pcpp::DoIpEntityStatusResponseCode::GATEWAY, 0, 0);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&data));
	doIpPacket.computeCalculateFields();
	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpEntityStatusResponse>();

	doipLayer->setNodeType(pcpp::DoIpEntityStatusResponseCode::GATEWAY);
	doipLayer->setMaxConcurrentSockets(5);
	doipLayer->setCurrentlyOpenSockets(2);
	PTF_ASSERT_FALSE(doipLayer->hasMaxDataSize());
	try
	{
		doipLayer->getMaxDataSize();
	}
	catch (const std::runtime_error& e)
	{
		PTF_ASSERT_EQUAL(std::string(e.what()), "Max data size field not present!");
	}
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 53);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (57 - 15), bytesWithoutMaxDataSize, 11);

	// add max data size
	const uint32_t maxDataSize = 0x11223344;
	doipLayer->setMaxDataSize(maxDataSize);

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 57);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (57 - 15), bytes, 15);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ENTITY_STATUS_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "DOIP entity status response");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 7);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DoIP Layer, DOIP entity status response (0x4002)");
	PTF_ASSERT_EQUAL(doipLayer->getNodeType(), pcpp::DoIpEntityStatusResponseCode::GATEWAY, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getMaxConcurrentSockets(), 5);
	PTF_ASSERT_EQUAL(doipLayer->getCurrentlyOpenSockets(), 2);
	PTF_ASSERT_TRUE(doipLayer->hasMaxDataSize());
	PTF_ASSERT_EQUAL(doipLayer->getMaxDataSize(), maxDataSize);
	doipLayer->clearMaxDataSize();
	PTF_ASSERT_FALSE(doipLayer->hasMaxDataSize());
}  // DoIpEntityStatusResponsePacketCreation

// DoIpDiagnosticMessagePacketParsing
PTF_TEST_CASE(DoIpDiagnosticMessagePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpDiagnosticMessagePacket.dat");

	pcpp::Packet DiagnosticMessagePacket(&rawPacket1);
	PTF_ASSERT_TRUE(DiagnosticMessagePacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(DiagnosticMessagePacket.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(DiagnosticMessagePacket.isPacketOfType(pcpp::DOIP));

	pcpp::TcpLayer* tcpLayer = DiagnosticMessagePacket.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = DiagnosticMessagePacket.getLayerOfType<pcpp::DoIpDiagnosticMessage>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	unsigned char bytes[] = { 0x2, 0xfd, 0x80, 0x1, 0x0, 0x0, 0x0, 0x6, 0xe, 0x80, 0x40, 0x10, 0x10, 0x3 };

	PTF_ASSERT_EQUAL(DiagnosticMessagePacket.getRawPacket()->getRawDataLen(), 68);
	PTF_ASSERT_BUF_COMPARE(DiagnosticMessagePacket.getRawPacket()->getRawData() + (68 - 14), bytes, 14);

	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Source Address: 0xe80\nTarget Address: 0x4010\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic message");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 6);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic message (0x8001)");
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0xe80);
	PTF_ASSERT_EQUAL(doipLayer->getTargetAddress(), 0x4010);
	const std::vector<uint8_t>& diagData{ 0x10, 0x03 };
	std::vector<uint8_t> actual = doipLayer->getDiagnosticData();
	PTF_ASSERT_VECTORS_EQUAL(actual, diagData);

}  // DoIpDiagnosticMessagePacketParsing

// DoIpDiagnosticMessagePacketCreation
PTF_TEST_CASE(DoIpDiagnosticMessagePacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x80, 0x1, 0x0, 0x0, 0x0, 0x6, 0x20, 0x30, 0x40, 0x40, 0x10, 0x02 };
	const std::vector<uint8_t>& diagnosticData{ 0x10, 0x02 };
	const std::vector<uint8_t>& diagnosticData2{ 0x10, 0x02, 0x40, 0x50 };
	pcpp::DoIpDiagnosticMessage data(0x2030, 0x4040, diagnosticData);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&data));
	doIpPacket.computeCalculateFields();
	// std::cout << pcpp::byteArrayToHexString(data.getDataPtr(0),14) << "\n";
	data.setDiagnosticData(diagnosticData);
	data.setDiagnosticData(diagnosticData2);
	data.setDiagnosticData(diagnosticData);

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 68);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (68 - 14), bytes, 14);
	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpDiagnosticMessage>();
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x2030);
	PTF_ASSERT_EQUAL(doipLayer->getTargetAddress(), 0x4040);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic message");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 6);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic message (0x8001)");
	doipLayer->setSourceAddress(0x8080);
	doipLayer->setTargetAddress(0x4343);
	std::vector<uint8_t> newDiagnosticData{ 0x10, 0x02, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0a };
	doipLayer->setDiagnosticData(newDiagnosticData);

	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x8080);
	PTF_ASSERT_EQUAL(doipLayer->getTargetAddress(), 0x4343);
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getDiagnosticData(), newDiagnosticData);
	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Source Address: 0x8080\nTarget Address: 0x4343\n");
}  // DoIpDiagnosticMessagePacketCreation

// DoIpDiagnosticAckMessagePacketParsing
PTF_TEST_CASE(DoIpDiagnosticAckMessagePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpDiagnosticAckMessagePacket.dat");

	pcpp::Packet DiagnosticAckMessage(&rawPacket1);
	PTF_ASSERT_TRUE(DiagnosticAckMessage.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(DiagnosticAckMessage.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(DiagnosticAckMessage.isPacketOfType(pcpp::DOIP));

	pcpp::TcpLayer* tcpLayer = DiagnosticAckMessage.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = DiagnosticAckMessage.getLayerOfType<pcpp::DoIpDiagnosticAckMessage>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getSummary(),
	                 "Source Address: 0x4010\nTarget Address: 0xe80\nACK code: ACK (0x0)\nPrevious message: 22f101\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic message Ack");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 8);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic message Ack (0x8002)");
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x4010);
	PTF_ASSERT_EQUAL(doipLayer->getTargetAddress(), 0x0e80);
	PTF_ASSERT_EQUAL(doipLayer->getAckCode(), pcpp::DoIpDiagnosticAckCodes::ACK, enumclass);
	PTF_ASSERT_TRUE(doipLayer->hasPreviousMessage());
	const std::vector<uint8_t>& prev{ 0X22, 0Xf1, 0x01 };
	PTF_ASSERT_TRUE(doipLayer->getPreviousMessage() == prev);
}  // DoIpDiagnosticAckMessagePacketParsing

// DoIpDiagnosticAckMessagePacketCreation
PTF_TEST_CASE(DoIpDiagnosticAckMessagePacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x80, 0x2, 0x0, 0x0, 0x0, 0x5, 0x40, 0x10, 0xe, 0x80, 0x0 };

	pcpp::DoIpDiagnosticAckMessage data(0x4010, 0xe80, pcpp::DoIpDiagnosticAckCodes::ACK);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&data));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 67);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (67 - 13), bytes, 13);
	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpDiagnosticAckMessage>();

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic message Ack");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 5);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic message Ack (0x8002)");
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x4010);
	PTF_ASSERT_EQUAL(doipLayer->getTargetAddress(), 0x0e80);
	PTF_ASSERT_EQUAL(doipLayer->getAckCode(), pcpp::DoIpDiagnosticAckCodes::ACK, enumclass);
	PTF_ASSERT_FALSE(doipLayer->hasPreviousMessage());
	const std::vector<uint8_t> nullprev = doipLayer->getPreviousMessage();
	const std::vector<uint8_t> expected{};
	PTF_ASSERT_VECTORS_EQUAL(nullprev, expected);

	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Source Address: 0x4010\nTarget Address: 0xe80\nACK code: ACK (0x0)\n");

	doipLayer->setSourceAddress(0x7080);
	doipLayer->setTargetAddress(0x9010);
	const std::vector<uint8_t>& prev = { 0x10, 0x20, 0x30, 0x40, 0x50 };
	doipLayer->setPreviousMessage(prev);
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x7080);
	PTF_ASSERT_EQUAL(doipLayer->getTargetAddress(), 0x9010);
	PTF_ASSERT_TRUE(doipLayer->hasPreviousMessage());
	PTF_ASSERT_TRUE(doipLayer->getPreviousMessage() == prev);

	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "Source Address: 0x7080\nTarget Address: 0x9010\nACK code: ACK (0x0)\nPrevious message: 1020304050\n");
	unsigned char newBytes[] = { 0x2,  0xfd, 0x80, 0x2, 0x0,  0x0,  0x0,  0xa,  0x70,
		                         0x80, 0x90, 0x10, 0x0, 0x10, 0x20, 0x30, 0x40, 0x50 };
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 72);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (72 - 18), newBytes, 18);
}  // DoIpDiagnosticAckMessagePacketCreation

// DoIpDiagnosticNackMessagePacketParsing
PTF_TEST_CASE(DoIpDiagnosticNackMessagePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpDiagnosticNackMessagePacket.dat");

	pcpp::Packet diagnosticNackPacket(&rawPacket1);
	PTF_ASSERT_TRUE(diagnosticNackPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(diagnosticNackPacket.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(diagnosticNackPacket.isPacketOfType(pcpp::DOIP));

	pcpp::TcpLayer* tcpLayer = diagnosticNackPacket.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);
	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* nackLayer = diagnosticNackPacket.getLayerOfType<pcpp::DoIpDiagnosticNackMessage>();
	PTF_ASSERT_NOT_NULL(nackLayer);

	PTF_ASSERT_EQUAL(nackLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(nackLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(nackLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK, enumclass);
	PTF_ASSERT_EQUAL(nackLayer->getPayloadTypeAsStr(), "Diagnostic message Nack");

	PTF_ASSERT_EQUAL(nackLayer->getPayloadLength(), 8);
	PTF_ASSERT_EQUAL(nackLayer->toString(), "DoIP Layer, Diagnostic message Nack (0x8003)");

	PTF_ASSERT_EQUAL(nackLayer->getSourceAddress(), 0x4010);
	PTF_ASSERT_EQUAL(nackLayer->getTargetAddress(), 0x0e80);
	PTF_ASSERT_EQUAL(nackLayer->getNackCode(), pcpp::DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS, enumclass);

	PTF_ASSERT_TRUE(nackLayer->hasPreviousMessage());
	const std::vector<uint8_t> expectedPrev = { 0x22, 0xF1, 0x01 };
	PTF_ASSERT_TRUE(nackLayer->getPreviousMessage() == expectedPrev);

	PTF_ASSERT_EQUAL(
	    nackLayer->getSummary(),
	    "Source Address: 0x4010\nTarget Address: 0xe80\nNACK code: Invalid source address (0x2)\nPrevious message: 22f101\n");
}  // DoIpDiagnosticNackMessagePacketParsing

// DoIpDiagnosticNackMessagePacketCreation
PTF_TEST_CASE(DoIpDiagnosticNackMessagePacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer((uint16_t)13400, (uint16_t)13400);
	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	// Create NACK message with no previous message
	pcpp::DoIpDiagnosticNackMessage nackMsg(0x4010, 0x0e80,
	                                        pcpp::DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS);
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&nackMsg));
	doIpPacket.computeCalculateFields();

	// Validate buffer content (13 bytes with no previous message)
	unsigned char bytes[] = { 0x2, 0xfd, 0x80, 0x3, 0x0, 0x0, 0x0, 0x5, 0x40, 0x10, 0x0e, 0x80, 0x02 };
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 67);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (67 - 13), bytes, 13);

	auto* layer = doIpPacket.getLayerOfType<pcpp::DoIpDiagnosticNackMessage>();
	PTF_ASSERT_EQUAL(layer->getSourceAddress(), 0x4010);
	PTF_ASSERT_EQUAL(layer->getTargetAddress(), 0x0e80);
	PTF_ASSERT_EQUAL(layer->getNackCode(), pcpp::DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS, enumclass);
	PTF_ASSERT_FALSE(layer->hasPreviousMessage());
	const std::vector<uint8_t> expectedPrev = {};
	PTF_ASSERT_TRUE(layer->getPreviousMessage() == expectedPrev);

	// Update fields and add previous message
	layer->setSourceAddress(0xDEAD);
	layer->setTargetAddress(0xBEEF);
	const std::vector<uint8_t> prevMsg = { 0xAA, 0xBB, 0xCC };
	layer->setPreviousMessage(prevMsg);

	PTF_ASSERT_EQUAL(layer->getSourceAddress(), 0xDEAD);
	PTF_ASSERT_EQUAL(layer->getTargetAddress(), 0xBEEF);
	PTF_ASSERT_TRUE(layer->hasPreviousMessage());
	PTF_ASSERT_TRUE(layer->getPreviousMessage() == prevMsg);

	PTF_ASSERT_EQUAL(
	    layer->getSummary(),
	    "Source Address: 0xdead\nTarget Address: 0xbeef\nNACK code: Invalid source address (0x2)\nPrevious message: aabbcc\n");

	// Validate full buffer again
	unsigned char newBytes[] = { 0x2,  0xfd, 0x80, 0x3,  0x0,  0x0,  0x0,  0x8,
		                         0xde, 0xad, 0xbe, 0xef, 0x02, 0xaa, 0xbb, 0xcc };
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 70);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (70 - 16), newBytes, 16);
}  // DoIpDiagnosticNackMessagePacketCreation

// DoIpPowerModeRequestPacketParsing
PTF_TEST_CASE(DoIpPowerModeRequestPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpPowerModeRequestPacket.dat");

	pcpp::Packet PowerModeRequest(&rawPacket1);
	PTF_ASSERT_TRUE(PowerModeRequest.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(PowerModeRequest.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(PowerModeRequest.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = PowerModeRequest.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = PowerModeRequest.getLayerOfType<pcpp::DoIpDiagnosticPowerModeRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic power mode request information");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic power mode request information (0x4003)")
}  // DoIpPowerModeRequestPacketParsing

// DoIpPowerModeRequestPacketCreation
PTF_TEST_CASE(DoIpPowerModeRequestPacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x40, 0x3, 0x0, 0x0, 0x0, 0x0 };
	pcpp::DoIpDiagnosticPowerModeRequest req;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&req));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), bytes, 8);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Diagnostic power mode request information");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DoIP Layer, Diagnostic power mode request information (0x4003)")
}  // DoIpPowerModeRequestPacketCreation

// DoIpEntityStatusRequestPacketParsing
PTF_TEST_CASE(DoIpEntityStatusRequestPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpEntityStatusRequestPacket.dat");

	pcpp::Packet EntityStatusRequest(&rawPacket1);
	PTF_ASSERT_TRUE(EntityStatusRequest.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(EntityStatusRequest.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(EntityStatusRequest.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = EntityStatusRequest.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x4988));

	auto* doipLayer = EntityStatusRequest.getLayerOfType<pcpp::DoIpEntityStatusRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ENTITY_STATUS_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "DOIP entity status request");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, DOIP entity status request (0x4001)")
}  // DoIpEntityStatusRequestPacketParsing

// DoIpEntityStatusRequestPacketCreation
PTF_TEST_CASE(DoIpEntityStatusRequestPacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x40, 0x1, 0x0, 0x0, 0x0, 0x0 };
	pcpp::DoIpEntityStatusRequest req;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&req));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), bytes, 8);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ENTITY_STATUS_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "DOIP entity status request");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DoIP Layer, DOIP entity status request (0x4001)")
}  // DoIpEntityStatusRequestPacketCreation

// DoIpAliveCheckRequestPacketParsing
PTF_TEST_CASE(DoIpAliveCheckRequestPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpAliveCheckRequestPacket.dat");

	pcpp::Packet AliveCheckRequest(&rawPacket1);
	PTF_ASSERT_TRUE(AliveCheckRequest.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(AliveCheckRequest.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(AliveCheckRequest.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = AliveCheckRequest.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = AliveCheckRequest.getLayerOfType<pcpp::DoIpAliveCheckRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Alive check request");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Alive check request (0x0007)")
}  // DoIpAliveCheckRequestPacketParsing

// DoIpAliveCheckRequestPacketCreation
PTF_TEST_CASE(DoIpAliveCheckRequestPacketCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer((uint16_t)13400, (uint16_t)13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char bytes[] = { 0x2, 0xfd, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0 };
	pcpp::DoIpAliveCheckRequest req;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&req));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), bytes, 8);
	auto* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpAliveCheckRequest>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Alive check request");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DoIP Layer, Alive check request (0x0007)")
}  // DoIpAliveCheckRequestPacketCreation

// DoIpVehicleIdentificationRequestWithDEfaultVersPacketParsing
PTF_TEST_CASE(DoIpVehicleIdentificationRequestWithDefaultVersPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestWithDefaultVersPacket.dat");

	pcpp::Packet vehicleIdentificationRequest(&rawPacket1);
	PTF_ASSERT_TRUE(vehicleIdentificationRequest.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(vehicleIdentificationRequest.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(vehicleIdentificationRequest.isPacketOfType(pcpp::DOIP));

	auto* udpLayer = vehicleIdentificationRequest.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::TCP_UDP_PORT);

	auto* doipLayer = vehicleIdentificationRequest.getLayerOfType<pcpp::DoIpVehicleIdentificationRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::DefaultVersion, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0x00);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request");
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Vehicle identification request (0x0001)");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x0);
}  // DoIpVehicleIdentificationRequestWithDEfaultVersPacketParsing

// DoIpInvalidPayloadTypePacketParsing
PTF_TEST_CASE(DoIpInvalidPayloadTypePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpInvalidPayloadTypePacket.dat");

	pcpp::Packet InvalidPayloadTypePacket(&rawPacket1);
	PTF_ASSERT_TRUE(InvalidPayloadTypePacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(InvalidPayloadTypePacket.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_FALSE(InvalidPayloadTypePacket.isPacketOfType(pcpp::DOIP));

}  // DoIpInvalidPayloadTypePacketParsing

// DoIpInvalidPayloadTypePacketPacketParsing
PTF_TEST_CASE(DoIpInvalidPayloadLenPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpWrongLengthRoutingActivationRequestPacket.dat");

	pcpp::Packet InvalidPayloadLenPacket(&rawPacket1);
	PTF_ASSERT_TRUE(InvalidPayloadLenPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(InvalidPayloadLenPacket.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_FALSE(InvalidPayloadLenPacket.isPacketOfType(pcpp::DOIP));

}  // DoIpInvalidPayloadTypePacketParsing

// DoIpInvalidProtocolVersion
PTF_TEST_CASE(DoIpInvalidProtocolVersionPacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpInvalidProtocolVersionPacket.dat");

	pcpp::Packet InvalidPayloadLenPacket(&rawPacket1);
	PTF_ASSERT_TRUE(InvalidPayloadLenPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(InvalidPayloadLenPacket.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_FALSE(InvalidPayloadLenPacket.isPacketOfType(pcpp::DOIP));

}  // DoIpInvalidProtocolVersion
