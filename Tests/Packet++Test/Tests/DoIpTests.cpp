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

// DoIpRoutActReqParsing
PTF_TEST_CASE(DoIpRoutActReqParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpRoutingActivationRequestPacket.dat");

	pcpp::Packet routingActivationRequestPacket(&rawPacket1);
	PTF_ASSERT_TRUE(routingActivationRequestPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = routingActivationRequestPacket.getLayerOfType<pcpp::DoIpRoutingActivationRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
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
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getReservedOem(), oemField);

	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "Source Address: 0xe80\nActivation type: Default (0x0)\nReserved by ISO: 00000000\nReserved by OEM: 00000000\n");
}  // DoIpRoutActReqParsing

// DoIpRoutActReqCreation
PTF_TEST_CASE(DoIpRoutActReqCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer(13400, 13400);

	tcpLayer.getTcpHeader()->windowSize = 64240;
	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char routingActivationRequestLayer[] = { 0x2, 0xfd, 0x0, 0x5, 0x0, 0x0,  0x0,  0xb,  0xe, 0x80,
		                                              0x0, 0x1,  0x2, 0x3, 0x4, 0x05, 0x05, 0x05, 0x05 };
	unsigned char routingActivationRequestLayerWithoutOem[] = { 0x2, 0xfd, 0x0, 0x5, 0x0, 0x0, 0x0, 0x7,
		                                                        0xe, 0x80, 0x0, 0x1, 0x2, 0x3, 0x4 };
	std::array<uint8_t, 4> isoReserved{ 0x1, 0x2, 0x3, 0x4 };
	std::array<uint8_t, 4> oemField{ 0x5, 0x5, 0x5, 0x5 };

	pcpp::DoIpRoutingActivationRequest doipLayer(0x0e80, pcpp::DoIpActivationTypes::DEFAULT);

	doipLayer.setReservedIso(isoReserved);
	doipLayer.setReservedOem(oemField);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer));
	doIpPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 73);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (73 - 19), routingActivationRequestLayer, 19);
	// check for setting invalid protocol version, will be applicable for all derived classes
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	doipLayer.setProtocolVersion(0x55);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::UNKNOWN, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersionAsStr(), "Unknown Protocol Version");
	doipLayer.setProtocolVersion(pcpp::DoIpProtocolVersion::ISO13400_2012);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);

	PTF_ASSERT_TRUE(doipLayer.hasReservedOem());
	PTF_ASSERT_VECTORS_EQUAL(doipLayer.getReservedOem(), oemField);

	doipLayer.clearReservedOem();

	PTF_ASSERT_FALSE(doipLayer.hasReservedOem());
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 73 - 4);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (73 - 4) - 15,
	                       routingActivationRequestLayerWithoutOem, 15);
	PTF_ASSERT_VECTORS_EQUAL(doipLayer.getReservedIso(), isoReserved);
	PTF_ASSERT_EQUAL(doipLayer.getSummary(),
	                 "Source Address: 0xe80\nActivation type: Default (0x0)\nReserved by ISO: 01020304\n");
	doipLayer.setReservedOem(oemField);
	PTF_ASSERT_TRUE(doipLayer.hasReservedOem());
	PTF_ASSERT_EQUAL(
	    doipLayer.getSummary(),
	    "Source Address: 0xe80\nActivation type: Default (0x0)\nReserved by ISO: 01020304\nReserved by OEM: 05050505\n");
}  // DoIpRoutActReqCreation

// DoIpRoutActResParsing
PTF_TEST_CASE(DoIpRoutActResParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpRoutingActivationResponsePacket.dat");

	pcpp::Packet routingActivationResponsePacket(&rawPacket1);
	PTF_ASSERT_TRUE(routingActivationResponsePacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = routingActivationResponsePacket.getLayerOfType<pcpp::DoIpRoutingActivationResponse>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
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
	PTF_ASSERT_RAISES(
	    doipLayer->getReservedOem(), std::runtime_error,
	    "Reserved OEM field not present!");  // Check that reserved OEM field is not present and raises an error
	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "Logical Address (Tester): 0xe80\nSource Address: 0x4010\nRouting activation response code: Routing successfully activated (0x10)\nReserved by ISO: 00000000\n");
}  // DoIpRoutActResParsing

// DoIpRoutActResCreation
PTF_TEST_CASE(DoIpRoutActResCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer(13400, 13400);

	tcpLayer.getTcpHeader()->windowSize = 64240;
	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char routingActivationResponseLayer[] = { 0x2,  0xfd, 0x0, 0x6, 0x0, 0x0, 0x0, 0xd, 0xe, 0x80, 0x40,
		                                               0x10, 0x10, 0x1, 0x2, 0x3, 0x4, 0x5, 0x5, 0x5, 0x5 };
	std::array<uint8_t, 4> resISO{ 0x1, 0x2, 0x3, 0x4 };
	std::array<uint8_t, 4> resOEM{ 0x5, 0x5, 0x5, 0x5 };

	pcpp::DoIpRoutingActivationResponse doipLayer(0x0e80, 0x4010,
	                                              pcpp::DoIpRoutingResponseCodes::ROUTING_SUCCESSFULLY_ACTIVATED);
	doipLayer.setReservedIso(resISO);
	doipLayer.setReservedOem(resOEM);

	// check for setting invalid protocol version, will be applicable for all derived classes
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	doipLayer.setProtocolVersion(0x55);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::UNKNOWN, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersionAsStr(), "Unknown Protocol Version");
	doipLayer.setProtocolVersion(pcpp::DoIpProtocolVersion::ISO13400_2012);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 75);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (75 - 21), routingActivationResponseLayer, 21);

	PTF_ASSERT_VECTORS_EQUAL(doipLayer.getReservedIso(), resISO);
	PTF_ASSERT_TRUE(doipLayer.hasReservedOem());
	PTF_ASSERT_VECTORS_EQUAL(doipLayer.getReservedOem(), resOEM);
	PTF_ASSERT_EQUAL(
	    doipLayer.getSummary(),
	    "Logical Address (Tester): 0xe80\nSource Address: 0x4010\nRouting activation response code: Routing successfully activated (0x10)\nReserved by ISO: 01020304\nReserved by OEM: 05050505\n");
	doipLayer.clearReservedOem();
	PTF_ASSERT_FALSE(doipLayer.hasReservedOem());
	PTF_ASSERT_EQUAL(
	    doipLayer.getSummary(),
	    "Logical Address (Tester): 0xe80\nSource Address: 0x4010\nRouting activation response code: Routing successfully activated (0x10)\nReserved by ISO: 01020304\n");
}  // DoIpRoutActResCreation

// DoIpGenHdrNackParsing
PTF_TEST_CASE(DoIpGenHdrNackParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpGenericHeaderNackPacket.dat");

	pcpp::Packet genericHeaderNackPacket(&rawPacket1);
	PTF_ASSERT_TRUE(genericHeaderNackPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = genericHeaderNackPacket.getLayerOfType<pcpp::DoIpGenericHeaderNack>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::GENERIC_HEADER_NACK, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Generic DOIP header Nack");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Generic DOIP header Nack (0x0000)");
	PTF_ASSERT_EQUAL(doipLayer->getNackCode(), pcpp::DoIpGenericHeaderNackCodes::UNKNOWN_PAYLOAD_TYPE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Generic header nack code: Unknown payload type (0x1)\n");
}  // DoIpGenHdrNackParsing

// DoIpGenHdrNackCreation
PTF_TEST_CASE(DoIpGenHdrNackCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char genericHeaderNackLayer[] = { 0x2, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 };
	pcpp::DoIpGenericHeaderNack doipLayer(pcpp::DoIpGenericHeaderNackCodes::UNKNOWN_PAYLOAD_TYPE);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer));
	doIpPacket.computeCalculateFields();

	// check for setting invalid protocol version, will be applicable for all derived classes
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	doipLayer.setProtocolVersion(0x55);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::UNKNOWN, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersionAsStr(), "Unknown Protocol Version");
	doipLayer.setProtocolVersion(pcpp::DoIpProtocolVersion::ISO13400_2012);
	PTF_ASSERT_EQUAL(doipLayer.getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 51);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (51 - 9), genericHeaderNackLayer, 9);

	PTF_ASSERT_EQUAL(doipLayer.getNackCode(), pcpp::DoIpGenericHeaderNackCodes::UNKNOWN_PAYLOAD_TYPE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer.getSummary(), "Generic header nack code: Unknown payload type (0x1)\n");
}  // DoIpGenHdrNackCreation

// DoIpVehIdenReqWithEIDParsing
PTF_TEST_CASE(DoIpVehIdenReqWithEIDParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestWithEIDPacket.dat");

	pcpp::Packet vehicleIdentificationRequestWEIDPacket(&rawPacket1);
	PTF_ASSERT_TRUE(vehicleIdentificationRequestWEIDPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer =
	    vehicleIdentificationRequestWEIDPacket.getLayerOfType<pcpp::DoIpVehicleIdentificationRequestWithEID>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "EID: 4241554e4545\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID,
	                 enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request with EID");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x6);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Vehicle identification request with EID (0x0002)")
	std::array<uint8_t, 6> eid{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45 };
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getEID(), eid);

}  // DoIpVehIdenReqWithEIDParsing

// DoIpVehIdenReqWithEIDCreation
PTF_TEST_CASE(DoIpVehIdenReqWithEIDCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(65300, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char vehicleIdentificationRequestWEIDLayer[] = { 0x2, 0xfd, 0x0,  0x2,  0x0,  0x0,  0x0,
		                                                      0x6, 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45 };
	std::array<uint8_t, 6> eid{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45 };

	pcpp::DoIpVehicleIdentificationRequestWithEID newVehicleIdentificationRequestWEID(eid);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newVehicleIdentificationRequestWEID));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 56);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (56 - 14), vehicleIdentificationRequestWEIDLayer,
	                       14);

	PTF_ASSERT_VECTORS_EQUAL(newVehicleIdentificationRequestWEID.getEID(), eid);
	PTF_ASSERT_EQUAL(newVehicleIdentificationRequestWEID.getSummary(), "EID: 4241554e4545\n");
}  // DoIpVehIdenReqWithEIDCreation

// DoIpVehIdenReqWithVINParsing
PTF_TEST_CASE(DoIpVehIdenReqWithVINParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestWithVINPacket.dat");

	pcpp::Packet vehicleIdentificationRequestWVINPacket(&rawPacket1);
	PTF_ASSERT_TRUE(vehicleIdentificationRequestWVINPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer =
	    vehicleIdentificationRequestWVINPacket.getLayerOfType<pcpp::DoIpVehicleIdentificationRequestWithVIN>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
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

}  // DoIpVehIdenReqWithVINParsing

// DoIpVehIdenReqWithVINCreation
PTF_TEST_CASE(DoIpVehIdenReqWithVINCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(65300, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char VehicleIdentificationRequestWVINLayer[] = { 0x2,  0xfd, 0x0,  0x3,  0x0,  0x0,  0x0,  0x11, 0x42,
		                                                      0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a, 0x31,
		                                                      0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };
	std::array<uint8_t, 17> vin{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a,
		                         0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };

	pcpp::DoIpVehicleIdentificationRequestWithVIN newVehicleIdentificationRequestWVIN(vin);
	newVehicleIdentificationRequestWVIN.setVIN(vin);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newVehicleIdentificationRequestWVIN));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 67);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (67 - 25), VehicleIdentificationRequestWVINLayer,
	                       25);

	PTF_ASSERT_EQUAL(newVehicleIdentificationRequestWVIN.getSummary(), "VIN: BAUNEE4MZ17042403\n");
	PTF_ASSERT_VECTORS_EQUAL(newVehicleIdentificationRequestWVIN.getVIN(), vin);
}  // DoIpVehIdenReqWithVINCreation

// DoIpVehAnnMessParsing
PTF_TEST_CASE(DoIpVehAnnMessParsing)
{
	// Dissect Vehicle Announcement message
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleAnnouncementMessagePacket.dat");

	std::array<uint8_t, 6> eid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, 6> gid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, 17> vin{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a,
		                         0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };

	pcpp::Packet vehicleAnnouncementPacket(&rawPacket1);
	PTF_ASSERT_TRUE(vehicleAnnouncementPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = vehicleAnnouncementPacket.getLayerOfType<pcpp::DoIpVehicleAnnouncementMessage>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "VIN: BAUNEE4MZ17042403\nLogical address: 0x4010\nEID: 001a37bfee74\nGID: 001a37bfee74\nFurther action required: No further action required (0x0)\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_ANNOUNCEMENT_MESSAGE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(),
	                 "Vehicle announcement message / vehicle identification response message");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 32);
	PTF_ASSERT_EQUAL(doipLayer->toString(),
	                 "DoIP Layer, Vehicle announcement message / vehicle identification response message (0x0004)");
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getVIN(), vin);
	PTF_ASSERT_EQUAL(doipLayer->getLogicalAddress(), 0x4010);
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getEID(), eid);
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getGID(), gid);
	PTF_ASSERT_EQUAL(doipLayer->getFurtherActionRequired(), pcpp::DoIpActionCodes::NO_FURTHER_ACTION_REQUIRED,
	                 enumclass);
	PTF_ASSERT_FALSE(doipLayer->hasSyncStatus());
	PTF_ASSERT_RAISES(doipLayer->getSyncStatus(), std::runtime_error, "Sync status field not present!");
}  // DoIpVehAnnMessParsing

// DoIpVehAnnMessCreation
PTF_TEST_CASE(DoIpVehAnnMessCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char vehicleAnnouncementLayer[] = { 0x2,  0xfd, 0x0,  0x4,  0x0,  0x0,  0x0,  0x21, 0x42, 0x41, 0x55,
		                                         0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a, 0x31, 0x37, 0x30, 0x34, 0x32,
		                                         0x34, 0x30, 0x33, 0x40, 0x10, 0x0,  0x1a, 0x37, 0xbf, 0xee, 0x74,
		                                         0x0,  0x1a, 0x37, 0xbf, 0xee, 0x74, 0x0,  0x0 };
	std::array<uint8_t, 6> eid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, 6> gid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, 17> vin{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a,
		                         0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };

	pcpp::DoIpVehicleAnnouncementMessage newVehicleAnnouncement(vin, 0x4010, eid, gid,
	                                                            pcpp::DoIpActionCodes::NO_FURTHER_ACTION_REQUIRED);
	newVehicleAnnouncement.setSyncStatus(pcpp::DoIpSyncStatus::VIN_AND_OR_GID_ARE_SINCHRONIZED);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newVehicleAnnouncement));
	doIpPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 83);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (83 - 41), vehicleAnnouncementLayer, 41);
	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpVehicleAnnouncementMessage>();
	PTF_ASSERT_NOT_NULL(doipLayer);

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
}  // DoIpVehAnnMessCreation

// DoIpVehIdenReqParsing
PTF_TEST_CASE(DoIpVehIdenReqParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestPacket.dat");

	pcpp::Packet vehicleIdentificationRequestPacket(&rawPacket1);
	PTF_ASSERT_TRUE(vehicleIdentificationRequestPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = vehicleIdentificationRequestPacket.getLayerOfType<pcpp::DoIpVehicleIdentificationRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request");
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Vehicle identification request (0x0001)");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x0);

}  // DoIpVehIdenReqParsing

// DoIpVehIdenReqCreation
PTF_TEST_CASE(DoIpVehIdenReqCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));

	ipLayer.getIPv4Header()->ipId = htobe16(20370);
	ipLayer.getIPv4Header()->timeToLive = 128;
	pcpp::UdpLayer udpLayer(65300, 13400);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));

	unsigned char vehicleIdentificationRequestLayer[] = { 0x2, 0xfd, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0 };

	pcpp::DoIpVehicleIdentificationRequest newVehicleIdentificationRequest;
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newVehicleIdentificationRequest));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), vehicleIdentificationRequestLayer, 8);
}  // DoIpVehIdenReqCreation

// DoIpAliveCheckRespParsing
PTF_TEST_CASE(DoIpAliveCheckRespParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpAliveCheckResponsePacket.dat");

	pcpp::Packet aliveCheckResponsePacket(&rawPacket1);
	PTF_ASSERT_TRUE(aliveCheckResponsePacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = aliveCheckResponsePacket.getLayerOfType<pcpp::DoIpAliveCheckResponse>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Alive check response");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 2);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Alive check response (0x0008)");
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x00);
	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Source Address: 0x0\n");
}  // DoIpAliveCheckRespParsing

// DoIpAliveCheckRespCreation
PTF_TEST_CASE(DoIpAliveCheckRespCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char aliveCheckResponseLayer[] = { 0x2, 0xfd, 0x0, 0x8, 0x0, 0x0, 0x0, 0x2, 0x10, 0x20 };
	pcpp::DoIpAliveCheckResponse newAliveCheckResponse(0x1020);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newAliveCheckResponse));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 52);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (52 - 10), aliveCheckResponseLayer, 10);
}  // DoIpAliveCheckRespCreation

// DoIpDiagPowerModeRespParsing
PTF_TEST_CASE(DoIpDiagPowerModeRespParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpPowerModeResponsePacket.dat");

	pcpp::Packet diagnosticPowerModeResponsePacket(&rawPacket1);
	PTF_ASSERT_TRUE(diagnosticPowerModeResponsePacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = diagnosticPowerModeResponsePacket.getLayerOfType<pcpp::DoIpDiagnosticPowerModeResponse>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Diagnostic power mode: Not ready (0x0)\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic power mode response information");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic power mode response information (0x4004)");
	PTF_ASSERT_EQUAL(doipLayer->getPowerModeCode(), pcpp::DoIpDiagnosticPowerModeCodes::NOT_READY, enumclass);
}  // DoIpDiagPowerModeRespParsing

// DoIpDiagPowerModeRespCreation
PTF_TEST_CASE(DoIpDiagPowerModeRespCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char diagnosticPowerModeResponseLayer[] = { 0x2, 0xfd, 0x40, 0x4, 0x0, 0x0, 0x0, 0x1, 0x1 };
	pcpp::DoIpDiagnosticPowerModeResponse newDiagnosticPowerModeResponse(pcpp::DoIpDiagnosticPowerModeCodes::READY);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newDiagnosticPowerModeResponse));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 51);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (51 - 9), diagnosticPowerModeResponseLayer, 9);
}  // DoIpDiagPowerModeRespCreation

// DoIpEntityStatusRespParsing
PTF_TEST_CASE(DoIpEntityStatusRespParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpEntityStatusResponsePacket.dat");

	pcpp::Packet entityStatusResponsePacket(&rawPacket1);
	PTF_ASSERT_TRUE(entityStatusResponsePacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = entityStatusResponsePacket.getLayerOfType<pcpp::DoIpEntityStatusResponse>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "Entity status: DoIP gateway (0x0)\nMax Concurrent Socket: 1\nCurrently Opened Socket: 0\nMax Data Size: 0x00000fff\n");

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
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
}  // DoIpEntityStatusRespParsing

// DoIpEntityStatusRespCreation
PTF_TEST_CASE(DoIpEntityStatusRespCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char entityStatusResponseWithoutMaxDataSizeLayer[] = { 0x2, 0xfd, 0x40, 0x2, 0x0, 0x0,
		                                                            0x0, 0x3,  0x0,  0x5, 0x2 };
	unsigned char entityStatusResponse[] = { 0x2, 0xfd, 0x40, 0x2,  0x0,  0x0,  0x0, 0x7,
		                                     0x0, 0x5,  0x2,  0x11, 0x22, 0x33, 0x44 };
	pcpp::DoIpEntityStatusResponse newEntityStatusResponse(pcpp::DoIpEntityStatusResponseCode::GATEWAY, 5, 2);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newEntityStatusResponse));
	doIpPacket.computeCalculateFields();

	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpEntityStatusResponse>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_FALSE(doipLayer->hasMaxDataSize());
	PTF_ASSERT_RAISES(
	    doipLayer->getMaxDataSize(), std::runtime_error,
	    "MaxDataSize field not present!");  // Check that max data size field is not present and raises an error
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 53);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (57 - 15),
	                       entityStatusResponseWithoutMaxDataSizeLayer, 11);

	// add max data size
	const uint32_t maxDataSize = 0x11223344;
	doipLayer->setMaxDataSize(maxDataSize);
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 57);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (57 - 15), entityStatusResponse, 15);

	PTF_ASSERT_TRUE(doipLayer->hasMaxDataSize());
	PTF_ASSERT_EQUAL(doipLayer->getMaxDataSize(), maxDataSize);

	doipLayer->clearMaxDataSize();
	PTF_ASSERT_FALSE(doipLayer->hasMaxDataSize());
	PTF_ASSERT_RAISES(doipLayer->getMaxDataSize(), std::runtime_error, "MaxDataSize field not present!");
}  // DoIpEntityStatusRespCreation

// DoIpDiagMessParsing
PTF_TEST_CASE(DoIpDiagMessParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpDiagnosticMessagePacket.dat");

	pcpp::Packet diagnosticMessagePacket(&rawPacket1);
	PTF_ASSERT_TRUE(diagnosticMessagePacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = diagnosticMessagePacket.getLayerOfType<pcpp::DoIpDiagnosticMessage>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	unsigned char diagnosticMessageLayer[] = { 0x2, 0xfd, 0x80, 0x1,  0x0,  0x0,  0x0,
		                                       0x6, 0xe,  0x80, 0x40, 0x10, 0x10, 0x3 };
	PTF_ASSERT_EQUAL(diagnosticMessagePacket.getRawPacket()->getRawDataLen(), 68);
	PTF_ASSERT_BUF_COMPARE(diagnosticMessagePacket.getRawPacket()->getRawData() + (68 - 14), diagnosticMessageLayer,
	                       14);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic message");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 6);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic message (0x8001)");
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0xe80);
	PTF_ASSERT_EQUAL(doipLayer->getTargetAddress(), 0x4010);
	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Source Address: 0xe80\nTarget Address: 0x4010\n");

	const std::vector<uint8_t>& diagData{ 0x10, 0x03 };
	std::vector<uint8_t> actual = doipLayer->getDiagnosticData();
	PTF_ASSERT_VECTORS_EQUAL(actual, diagData);

}  // DoIpDiagMessParsing

// DoIpDiagMessCreation
PTF_TEST_CASE(DoIpDiagMessCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char diagnosticMessageLayer[] = { 0x2, 0xfd, 0x80, 0x1,  0x0,  0x0,  0x0,
		                                       0x6, 0x20, 0x30, 0x40, 0x40, 0x10, 0x02 };
	const std::vector<uint8_t>& diagnosticData{ 0x10, 0x02 };
	pcpp::DoIpDiagnosticMessage newDiagnosticMessage(0x2030, 0x4040, diagnosticData);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newDiagnosticMessage));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 66);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (66 - 12), diagnosticMessageLayer, 12);

	std::vector<uint8_t> newDiagnosticData{ 0x10, 0x02, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0a };
	newDiagnosticMessage.setDiagnosticData(newDiagnosticData);

	PTF_ASSERT_VECTORS_EQUAL(newDiagnosticMessage.getDiagnosticData(), newDiagnosticData);
	PTF_ASSERT_EQUAL(newDiagnosticMessage.getSummary(), "Source Address: 0x2030\nTarget Address: 0x4040\n");
}  // DoIpDiagMessCreation

// DoIpDiagMessAckParsing
PTF_TEST_CASE(DoIpDiagMessAckParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpDiagnosticMessageAckPacket.dat");

	pcpp::Packet diagnosticAckMessagePacket(&rawPacket1);
	PTF_ASSERT_TRUE(diagnosticAckMessagePacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = diagnosticAckMessagePacket.getLayerOfType<pcpp::DoIpDiagnosticMessageAck>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_ACK, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic message Ack");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 8);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic message Ack (0x8002)");
	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0x4010);
	PTF_ASSERT_EQUAL(doipLayer->getTargetAddress(), 0x0e80);
	PTF_ASSERT_EQUAL(doipLayer->getAckCode(), pcpp::DoIpDiagnosticAckCodes::ACK, enumclass);
	PTF_ASSERT_TRUE(doipLayer->hasPreviousMessage());
	const std::vector<uint8_t>& prev{ 0X22, 0Xf1, 0x01 };
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getPreviousMessage(), prev);
	PTF_ASSERT_EQUAL(doipLayer->getSummary(),
	                 "Source Address: 0x4010\nTarget Address: 0xe80\nACK code: ACK (0x0)\nPrevious message: 22f101\n");

}  // DoIpDiagMessAckParsing

// DoIpDiagMessAckCreation
PTF_TEST_CASE(DoIpDiagMessAckCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char diagnosticAckMessageLayer[] = {
		0x2, 0xfd, 0x80, 0x2, 0x0, 0x0, 0x0, 0x5, 0x40, 0x10, 0xe, 0x80, 0x0
	};
	pcpp::DoIpDiagnosticMessageAck newDiagnosticAckMessage(0x4010, 0xe80, pcpp::DoIpDiagnosticAckCodes::ACK);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newDiagnosticAckMessage));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 67);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (67 - 13), diagnosticAckMessageLayer, 13);
	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpDiagnosticMessageAck>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_FALSE(doipLayer->hasPreviousMessage());
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getPreviousMessage(), std::vector<uint8_t>{});

	PTF_ASSERT_EQUAL(doipLayer->getSummary(), "Source Address: 0x4010\nTarget Address: 0xe80\nACK code: ACK (0x0)\n");

	doipLayer->setSourceAddress(0x7080);
	doipLayer->setTargetAddress(0x9010);

	const std::vector<uint8_t>& previousMessage = { 0x10, 0x20, 0x30, 0x40, 0x50 };
	const std::vector<uint8_t>& newPreviousMessage = { 0x10, 0x20 };
	doipLayer->setPreviousMessage(previousMessage);

	PTF_ASSERT_TRUE(doipLayer->hasPreviousMessage());
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getPreviousMessage(), previousMessage);

	doipLayer->setPreviousMessage(newPreviousMessage);
	PTF_ASSERT_TRUE(doipLayer->hasPreviousMessage());
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getPreviousMessage(), newPreviousMessage);

	doipLayer->setPreviousMessage(previousMessage);

	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "Source Address: 0x7080\nTarget Address: 0x9010\nACK code: ACK (0x0)\nPrevious message: 1020304050\n");
	unsigned char newDiagnosticAckWPreviousMessage[] = { 0x2,  0xfd, 0x80, 0x2, 0x0,  0x0,  0x0,  0xa,  0x70,
		                                                 0x80, 0x90, 0x10, 0x0, 0x10, 0x20, 0x30, 0x40, 0x50 };
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 72);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (72 - 18), newDiagnosticAckWPreviousMessage, 18);
}  // DoIpDiagMessAckCreation

// DoIpDiagMessNackParsing
PTF_TEST_CASE(DoIpDiagMessNackParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpDiagnosticMessageNackPacket.dat");

	pcpp::Packet diagnosticNackPacket(&rawPacket1);
	PTF_ASSERT_TRUE(diagnosticNackPacket.isPacketOfType(pcpp::DOIP));

	auto* nackLayer = diagnosticNackPacket.getLayerOfType<pcpp::DoIpDiagnosticMessageNack>();
	PTF_ASSERT_NOT_NULL(nackLayer);

	PTF_ASSERT_EQUAL(nackLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(nackLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(nackLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(nackLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NACK, enumclass);
	PTF_ASSERT_EQUAL(nackLayer->getPayloadTypeAsStr(), "Diagnostic message Nack");
	PTF_ASSERT_EQUAL(nackLayer->getPayloadLength(), 8);
	PTF_ASSERT_EQUAL(nackLayer->toString(), "DoIP Layer, Diagnostic message Nack (0x8003)");
	PTF_ASSERT_EQUAL(nackLayer->getSourceAddress(), 0x4010);
	PTF_ASSERT_EQUAL(nackLayer->getTargetAddress(), 0x0e80);
	PTF_ASSERT_EQUAL(nackLayer->getNackCode(), pcpp::DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS, enumclass);
	PTF_ASSERT_TRUE(nackLayer->hasPreviousMessage());

	const std::vector<uint8_t> expectedPreviousMessage = { 0x22, 0xF1, 0x01 };
	PTF_ASSERT_VECTORS_EQUAL(nackLayer->getPreviousMessage(), expectedPreviousMessage);

	PTF_ASSERT_EQUAL(
	    nackLayer->getSummary(),
	    "Source Address: 0x4010\nTarget Address: 0xe80\nNACK code: Invalid source address (0x2)\nPrevious message: 22f101\n");
}  // DoIpDiagMessNackParsing

// DoIpDiagMessNackCreation
PTF_TEST_CASE(DoIpDiagMessNackCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::TcpLayer tcpLayer(13400, 13400);
	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&tcpLayer));
	doIpPacket.computeCalculateFields();

	// Create NACK message with no previous message
	pcpp::DoIpDiagnosticMessageNack newDiagnosticnackMessage(
	    0x4010, 0x0e80, pcpp::DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS);
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newDiagnosticnackMessage));
	doIpPacket.computeCalculateFields();

	// Validate buffer content (13 bytes with no previous message)
	unsigned char diagnosticnackMessageLayer[] = { 0x2, 0xfd, 0x80, 0x3,  0x0,  0x0, 0x0,
		                                           0x5, 0x40, 0x10, 0x0e, 0x80, 0x02 };
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 67);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (67 - 13), diagnosticnackMessageLayer, 13);

	auto* doipLayer = doIpPacket.getLayerOfType<pcpp::DoIpDiagnosticMessageNack>();

	PTF_ASSERT_FALSE(doipLayer->hasPreviousMessage());
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getPreviousMessage(), std::vector<uint8_t>{});

	// Update fields and add previous message
	doipLayer->setSourceAddress(0xDEAD);
	doipLayer->setTargetAddress(0xBEEF);
	const std::vector<uint8_t> previousMessage = { 0xAA, 0xBB, 0xCC };
	doipLayer->setPreviousMessage(previousMessage);

	PTF_ASSERT_EQUAL(doipLayer->getSourceAddress(), 0xDEAD);
	PTF_ASSERT_EQUAL(doipLayer->getTargetAddress(), 0xBEEF);
	PTF_ASSERT_TRUE(doipLayer->hasPreviousMessage());
	PTF_ASSERT_VECTORS_EQUAL(doipLayer->getPreviousMessage(), previousMessage);

	PTF_ASSERT_EQUAL(
	    doipLayer->getSummary(),
	    "Source Address: 0xdead\nTarget Address: 0xbeef\nNACK code: Invalid source address (0x2)\nPrevious message: aabbcc\n");

	// Validate full buffer again
	unsigned char diagnosticnackMessageLayerWPreviousMessage[] = { 0x2,  0xfd, 0x80, 0x3,  0x0,  0x0,  0x0,  0x8,
		                                                           0xde, 0xad, 0xbe, 0xef, 0x02, 0xaa, 0xbb, 0xcc };
	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 70);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (70 - 16),
	                       diagnosticnackMessageLayerWPreviousMessage, 16);
}  // DoIpDiagMessNackCreation

// DoIpDiagPowerModeReqParsing
PTF_TEST_CASE(DoIpDiagPowerModeReqParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpPowerModeRequestPacket.dat");

	pcpp::Packet diagnosticPowerModeRequestPacket(&rawPacket1);
	PTF_ASSERT_TRUE(diagnosticPowerModeRequestPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = diagnosticPowerModeRequestPacket.getLayerOfType<pcpp::DoIpDiagnosticPowerModeRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic power mode request information");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Diagnostic power mode request information (0x4003)")
}  // DoIpDiagPowerModeReqParsing

// DoIpDiagPowerModeReqCreation
PTF_TEST_CASE(DoIpDiagPowerModeReqCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char diagnosticPowerModeLayer[] = { 0x2, 0xfd, 0x40, 0x3, 0x0, 0x0, 0x0, 0x0 };
	pcpp::DoIpDiagnosticPowerModeRequest newDiagnosticPowerModeRequest;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newDiagnosticPowerModeRequest));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), diagnosticPowerModeLayer, 8);
}  // DoIpDiagPowerModeReqCreation

// DoIpEntityStatusReqParsing
PTF_TEST_CASE(DoIpEntityStatusReqParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpEntityStatusRequestPacket.dat");

	pcpp::Packet entityStatusRequestPacket(&rawPacket1);
	PTF_ASSERT_TRUE(entityStatusRequestPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = entityStatusRequestPacket.getLayerOfType<pcpp::DoIpEntityStatusRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ENTITY_STATUS_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "DOIP entity status request");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, DOIP entity status request (0x4001)")
}  // DoIpEntityStatusReqParsing

// DoIpEntityStatusReqCreation
PTF_TEST_CASE(DoIpEntityStatusReqCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char entityStatusRequestLayer[] = { 0x2, 0xfd, 0x40, 0x1, 0x0, 0x0, 0x0, 0x0 };
	pcpp::DoIpEntityStatusRequest newEntityStatusRequest;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&newEntityStatusRequest));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), entityStatusRequestLayer, 8);
}  // DoIpEntityStatusReqCreation

// DoIpAliveCheckReqParsing
PTF_TEST_CASE(DoIpAliveCheckReqParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpAliveCheckRequestPacket.dat");

	pcpp::Packet aliveCheckRequestPacket(&rawPacket1);
	PTF_ASSERT_TRUE(aliveCheckRequestPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = aliveCheckRequestPacket.getLayerOfType<pcpp::DoIpAliveCheckRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::ISO13400_2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "DoIP ISO 13400-2:2012");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Alive check request");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Alive check request (0x0007)")
}  // DoIpAliveCheckReqParsing

// DoIpAliveCheckReqCreation
PTF_TEST_CASE(DoIpAliveCheckReqCreation)
{
	pcpp::Packet doIpPacket(100);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("00:13:72:25:fa:cd"), pcpp::MacAddress("00:e0:b1:49:39:02"));
	pcpp::IPv4Layer ipLayer(pcpp::IPv4Address("172.22.178.234"), pcpp::IPv4Address("10.10.8.240"));
	pcpp::UdpLayer udpLayer(13400, 13400);

	ipLayer.getIPv4Header()->timeToLive = 128;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&ipLayer));
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&udpLayer));
	doIpPacket.computeCalculateFields();

	unsigned char aliveCheckRequestLayer[] = { 0x2, 0xfd, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0 };
	pcpp::DoIpAliveCheckRequest req;

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&req));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), aliveCheckRequestLayer, 8);
}  // DoIpAliveCheckReqCreation

// DoIpVehIdenReqWithDefVersParsing
PTF_TEST_CASE(DoIpVehIdenReqWithDefVersParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestWithDefaultVersPacket.dat");

	pcpp::Packet vehicleIdentificationRequestPacket(&rawPacket1);
	PTF_ASSERT_TRUE(vehicleIdentificationRequestPacket.isPacketOfType(pcpp::DOIP));

	auto* doipLayer = vehicleIdentificationRequestPacket.getLayerOfType<pcpp::DoIpVehicleIdentificationRequest>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::DEFAULT_VALUE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersionAsStr(), "Default value for vehicle identification request messages");
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0x00);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request");
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DoIP Layer, Vehicle identification request (0x0001)");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x0);
}  // DoIpVehIdenReqWithDefVersParsing

// DoIpInvalidPackets
PTF_TEST_CASE(DoIpInvalidPackets)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpInvalidPayloadTypePacket.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/DoIpWrongLengthRoutingActivationRequestPacket.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/DoIpInvalidProtocolVersionPacket.dat");

	pcpp::Packet invalidPayloadTypePacket(&rawPacket1);
	PTF_ASSERT_FALSE(invalidPayloadTypePacket.isPacketOfType(pcpp::DOIP));

	pcpp::Packet wrongLengthRoutingActivationRequestPacket(&rawPacket2);
	PTF_ASSERT_FALSE(wrongLengthRoutingActivationRequestPacket.isPacketOfType(pcpp::DOIP));

	pcpp::Packet invalidProtocolVersionPacket(&rawPacket3);
	PTF_ASSERT_FALSE(invalidProtocolVersionPacket.isPacketOfType(pcpp::DOIP));

}  // DoIpInvalidPackets
