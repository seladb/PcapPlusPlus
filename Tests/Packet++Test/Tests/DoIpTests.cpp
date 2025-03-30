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
#include "DoIpLayerData.h"
#include <memory>

// ------------------
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

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x8886));

	pcpp::DoIpLayer* doipLayer = GenericHeaderNack.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	// build doipData from existent layer
	pcpp::GenericHeaderNackData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(data.toString(), "generic header nack code: Unknown payload type (0x1)\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Generic DOIP header Nack");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Generic DOIP header Nack (0x0000)")
}

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
	pcpp::GenericHeaderNackData data;
	data.genericNackCode = pcpp::DoIpGenericHeaderNackCodes::UNKNOWN_PAYLOAD_TYPE;
	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK, &data);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 51);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (51 - 9), bytes, 9);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::GENERIC_HEADER_NEG_ACK, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Generic DOIP header Nack");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Generic DOIP header Nack (0x0000)")
}
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

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x8988));
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->length, be16toh(0x10));

	// DOIP fields for vehicle identification request
	pcpp::DoIpLayer* doipLayer = vehicleIdentificationRequest.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	// PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request");
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Vehicle identification request (0x0001)");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x0);

}  // DoIpVehicleIdentificationRequestPacketParsing

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

	// vehIdentificationRequestArgs.args = std::monostate{};

	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST);
	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), bytes, 8);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Vehicle identification request");
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Vehicle identification request (0x0001)");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 0x0);
}
// VehicleIdentificationWithVIN
PTF_TEST_CASE(DoIpVehicleIdentificationRequestVINPacketParsing)
{
	// Dissect Vehicle identification Request with VIN
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestVINPacket.dat");

	pcpp::Packet VehicleIdentificationRequestVIN(&rawPacket1);
	PTF_ASSERT_TRUE(VehicleIdentificationRequestVIN.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(VehicleIdentificationRequestVIN.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(VehicleIdentificationRequestVIN.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = VehicleIdentificationRequestVIN.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x4b6d));
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->length, be16toh(33));

	// DOIP fields for vehicle identification request
	pcpp::DoIpLayer* doipLayer = VehicleIdentificationRequestVIN.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	// build doipData from existent layer
	pcpp::VehicleIdentificationRequestVINData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(data.toString(), "VIN: BAUNEE4MZ17042403\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN,
	                 enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request with VIN");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x11);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Vehicle identification request with VIN (0x0003)")

}  // DoIpVehicleIdentificationRequestVINPacketParsing

PTF_TEST_CASE(DoIpVehicleIdentificationRequestVINPacketCreation)
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
	std::array<uint8_t, DOIP_VIN_LEN> vin{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a,
		                                   0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };

	pcpp::VehicleIdentificationRequestVINData withVin;
	withVin.vin = vin;

	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN, &withVin);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 67);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (67 - 25), bytes, 25);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN,
	                 enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Vehicle identification request with VIN");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 17);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Vehicle identification request with VIN (0x0003)")
}
// VehicleIdentificationWithEID
PTF_TEST_CASE(DoIpVehicleIdentificationRequestEIDPacketParsing)
{
	// Dissect Vehicle identification Request with EID
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleIdentificationRequestEIDPacket.dat");

	pcpp::Packet VehicleIdentificationRequestEID(&rawPacket1);
	PTF_ASSERT_TRUE(VehicleIdentificationRequestEID.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(VehicleIdentificationRequestEID.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(VehicleIdentificationRequestEID.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = VehicleIdentificationRequestEID.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x7a80));
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->length, be16toh(0x16));

	// DOIP fields for vehicle identification request
	pcpp::DoIpLayer* doipLayer = VehicleIdentificationRequestEID.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	// build doipData from existent layer
	pcpp::VehicleIdentificationRequestEIDData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(data.toString(), "EID: 4241554e4545\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID,
	                 enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request with EID");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x6);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Vehicle identification request with EID (0x0002)")

}  // DoIpVehicleIdentificationRequestVINPacketParsing

PTF_TEST_CASE(DoIpVehicleIdentificationRequestEIDPacketCreation)
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
	std::array<uint8_t, DOIP_EID_LEN> eid{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45 };

	pcpp::VehicleIdentificationRequestEIDData withEID;
	withEID.eid = eid;

	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN, &withEID);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 56);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (56 - 14), bytes, 14);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST_WITH_EID,
	                 enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Vehicle identification request with EID");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 6);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Vehicle identification request with EID (0x0002)")
}
// VehicleAnnouncement
PTF_TEST_CASE(DoIpVehicleAnnouncementPacketParsing)
{
	// Dissect Vehicle Announcement message
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpVehicleAnnouncementPacket.dat");

	pcpp::Packet VehicleAnnouncement(&rawPacket1);
	PTF_ASSERT_TRUE(VehicleAnnouncement.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(VehicleAnnouncement.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(VehicleAnnouncement.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = VehicleAnnouncement.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 13400);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0xdf5e));
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->length, be16toh(0x30));

	// DOIP fields for vehicle identification request
	pcpp::DoIpLayer* doipLayer = VehicleAnnouncement.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	// build doipData from existent layer
	pcpp::VehicleAnnouncementData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(
		    data.toString(),
		    "VIN: BAUNEE4MZ17042403\nlogical address: 0x4010\nEID: 001a37bfee74\nGID: 001a37bfee74\nfurther action required:No further action required (0x0)\nVIN/GID sync status: NULL\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(),
	                 "Vehicle announcement message / vehicle identification response message");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 32);
	PTF_ASSERT_EQUAL(doipLayer->toString(),
	                 "DOIP Layer, Vehicle announcement message / vehicle identification response message (0x0004)")

}  // DoIpVehicleAnnouncementPacketParsing

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
	std::array<uint8_t, DOIP_EID_LEN> eid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, DOIP_EID_LEN> gid{ 0x0, 0x1a, 0x37, 0xbf, 0xee, 0x74 };
	std::array<uint8_t, DOIP_VIN_LEN> vin{ 0x42, 0x41, 0x55, 0x4e, 0x45, 0x45, 0x34, 0x4d, 0x5a,
		                                   0x31, 0x37, 0x30, 0x34, 0x32, 0x34, 0x30, 0x33 };

	pcpp::VehicleAnnouncementData ann;
	ann.gid = gid;
	ann.eid = eid;
	ann.vin = vin;
	ann.logicalAddress = be16toh(0x4010);
	ann.syncStatus = pcpp::DoIpSyncStatus::VIN_AND_OR_GID_ARE_SINCHRONIZED;
	ann.furtherActionRequired = pcpp::DoIpActionCodes::NO_FURTHER_ACTION_REQUIRED;

	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE, &ann);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 83);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (83 - 41), bytes, 41);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ANNOUNCEMENT_MESSAGE, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(),
	                 "Vehicle announcement message / vehicle identification response message");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 33);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(),
	                 "DOIP Layer, Vehicle announcement message / vehicle identification response message (0x0004)")
}
// RoutingActivationRequest
PTF_TEST_CASE(DoIpRoutingActivationRequestPacketParsing)
{
	// Dissect Vehicle Announcement message
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpRoutingActivationRequestPacket.dat");

	pcpp::Packet RoutingActivationRequest(&rawPacket1);
	PTF_ASSERT_TRUE(RoutingActivationRequest.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(RoutingActivationRequest.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(RoutingActivationRequest.isPacketOfType(pcpp::DOIP));

	pcpp::TcpLayer* tcpLayer = RoutingActivationRequest.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getDstPort(), pcpp::DoIpPorts::TCP_PORT);
	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), 53850);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->headerChecksum, be16toh(0x4008));

	pcpp::DoIpLayer* doipLayer = RoutingActivationRequest.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	// build doipData from existent layer
	pcpp::RoutingActivationRequestData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();

		PTF_ASSERT_EQUAL(
		    data.toString(),
		    "sourceAddress: 0xe80\nactivation type: Default (0x0)\nreserved by ISO: 00000000\nReserved by OEM: 00000000\n");
	// wrong build

	pcpp::RoutingActivationResponseData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Routing activation request");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 11);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Routing activation request (0x0005)")
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

	unsigned char bytes[] = { 0x2, 0xfd, 0x0, 0x5, 0x0, 0x0, 0x0, 0xb, 0xe, 0x80,
		                      0x0, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	pcpp::RoutingActivationRequestData routingData;
	routingData.sourceAddress = be16toh(0x0e80);
	routingData.activationType = pcpp::DoIpActivationTypes::Default;
	routingData.reservedIso = { 0x0, 0x0, 0x0, 0x0 };
	routingData.reservedOem = std::unique_ptr<std::array<uint8_t, 4>>(new std::array<uint8_t, 4>());

	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST, &routingData);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 73);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (73 - 19), bytes, 19);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Routing activation request");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 11);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Routing activation request (0x0005)")
}
// RoutingActivationResponse
PTF_TEST_CASE(DoIpRoutingActivationResponsePacketParsing)
{
	// Dissect Vehicle Announcement message
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
	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_PORT);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->headerChecksum, be16toh(0xa0a5));

	pcpp::DoIpLayer* doipLayer = RoutingActivationResponse.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	pcpp::RoutingActivationResponseData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(
		    data.toString(),
		    "logical address of external tester: 0xe80\nsource address: 0x4010\nrouting activation response code: Routing successfully activated (0x10)\nreserved by ISO: 00000000\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Routing activation response");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 9);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Routing activation response (0x0006)")
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
		                      0x10, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	pcpp::RoutingActivationResponseData routingData;
	routingData.logicalAddressExternalTester = be16toh(0x0e80);
	routingData.sourceAddress = be16toh(0x4010);
	routingData.responseCode = pcpp::DoIpRoutingResponseCodes::ROUTING_SUCCESSFULLY_ACTIVATED;
	routingData.reservedIso = { 0x0, 0x0, 0x0, 0x0 };
	routingData.reservedOem = std::unique_ptr<std::array<uint8_t, 4>>(new std::array<uint8_t, 4>());

	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE, &routingData);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 75);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (75 - 21), bytes, 21);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ROUTING_ACTIVATION_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Routing activation response");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 13);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Routing activation response (0x0006)")
}
// ---------------
// AliveCheckRequestPacket
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

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x8982));

	pcpp::DoIpLayer* doipLayer = AliveCheckRequest.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Alive check request");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Alive check request (0x0007)")
}

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

	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::ALIVE_CHECK_REQUEST);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), bytes, 8);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Alive check request");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Alive check request (0x0007)")
}
// ---------------
// AliveCheckResponsePacket
PTF_TEST_CASE(DoIpAliveCheckResponsePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpAliveCheckResponsePacket.dat");

	pcpp::Packet AliveCheckResponse(&rawPacket1);
	PTF_ASSERT_TRUE(AliveCheckResponse.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(AliveCheckResponse.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(AliveCheckResponse.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = AliveCheckResponse.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x897b));

	pcpp::DoIpLayer* doipLayer = AliveCheckResponse.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	// build doipData from existent layer
	pcpp::AliveCheckResponseData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(data.toString(), "source address: 0x0\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Alive check response");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 2);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Alive check response (0x0008)")
}

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

	unsigned char bytes[] = { 0x2, 0xfd, 0x0, 0x8, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0 };
	pcpp::AliveCheckResponseData aliveCheckRespData;
	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::ALIVE_CHECK_RESPONSE, &aliveCheckRespData);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 52);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (52 - 10), bytes, 10);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ALIVE_CHECK_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Alive check response");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 2);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Alive check response (0x0008)")
}
// ------------------
// EntityStatusRequestPacket
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

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x4988));

	pcpp::DoIpLayer* doipLayer = EntityStatusRequest.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ENTITY_STATUS_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "DOIP entity status request");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, DOIP entity status request (0x4001)")
}

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
	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::ENTITY_STATUS_REQUEST);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), bytes, 8);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ENTITY_STATUS_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "DOIP entity status request");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, DOIP entity status request (0x4001)")
}
// ------------------
// EntityStatusResponsePacket
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

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x4a61));

	pcpp::DoIpLayer* doipLayer = EntityStatusResponse.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	pcpp::EntityStatusResponseData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(
		    data.toString(),
		    "Entity status: DoIP gateway (0x0)\nmaximum Concurrent Socket: 1\ncurrently Opened Socket: 0\nmaximum Data Size: 0x00000fff\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::ENTITY_STATUS_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "DOIP entity status response");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 7);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, DOIP entity status response (0x4002)")
}

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

	unsigned char bytes[] = { 0x2, 0xfd, 0x40, 0x2, 0x0, 0x0, 0x0, 0x7, 0x0, 0x2, 0x2, 0x0, 0x0, 0xf, 0xff };
	pcpp::EntityStatusResponseData entityResponseData;
	entityResponseData.currentlyOpenSockets = 2;
	entityResponseData.maxConcurrentSockets = 2;
	entityResponseData.maxDataSize =
	    std::unique_ptr<std::array<uint8_t, 4>>(new std::array<uint8_t, 4>{ 0x0, 0x0, 0xf, 0xff });
	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::ENTITY_STATUS_RESPONSE, &entityResponseData);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 57);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (57 - 15), bytes, 15);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::ENTITY_STATUS_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "DOIP entity status response");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 7);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, DOIP entity status response (0x4002)")
}
// ------------------
// PowerModeRequestPacket
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

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x4986));

	pcpp::DoIpLayer* doipLayer = PowerModeRequest.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic power mode request information");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Diagnostic power mode request information (0x4003)")
}

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
	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 50);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (50 - 8), bytes, 8);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Diagnostic power mode request information");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 0);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Diagnostic power mode request information (0x4003)")
}
// ------------------
// PowerModeResponsePacket
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
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), pcpp::DoIpPorts::UDP_PORT);
	// PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x2e2a));

	pcpp::DoIpLayer* doipLayer = PowerModeResponse.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	pcpp::DiagnosticPowerModeResponseData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(data.toString(), "diagnostic power mode: not ready (0x0)\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic power mode response information");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Diagnostic power mode response information (0x4004)")
}

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

	unsigned char bytes[] = { 0x2, 0xfd, 0x40, 0x4, 0x0, 0x0, 0x0, 0x1, 0x0 };
	pcpp::DiagnosticPowerModeResponseData data;
	data.powerModeCode = pcpp::DoIpDiagnosticPowerModeCodes::NOT_READY;
	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE, &data);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 51);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (51 - 9), bytes, 9);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_POWER_MODE_RESPONSE, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Diagnostic power mode response information");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 1);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Diagnostic power mode response information (0x4004)")
}
// ------------------
// DiagnosticMessagePacket
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

	PTF_ASSERT_EQUAL(tcpLayer->getDstPort(), pcpp::DoIpPorts::TCP_PORT);
	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), 53854);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->headerChecksum, be16toh(0x4003));

	pcpp::DoIpLayer* doipLayer = DiagnosticMessagePacket.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	pcpp::DiagnosticMessageData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(data.toString(), "source address: 0xe80\ntarget address: 0x4010\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic message");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 6);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Diagnostic message (0x8001)")
}

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

	unsigned char bytes[] = { 0x2, 0xfd, 0x80, 0x1, 0x0, 0x0, 0x0, 0x6, 0xe, 0x80, 0x40, 0x10, 0x10, 0x3 };
	std::vector<uint8_t> diagnosticData{ 0x10, 0x03 };

	pcpp::DiagnosticMessageData data;
	data.sourceAddress = be16toh(0x0e80);
	data.targetAddress = be16toh(0x4010);
	data.diagnosticData = diagnosticData;
	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE, &data);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 68);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (68 - 14), bytes, 14);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_TYPE, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Diagnostic message");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 6);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Diagnostic message (0x8001)");
}
// ------------------
// DiagnosticAckMessagePacket
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

	PTF_ASSERT_EQUAL(tcpLayer->getDstPort(), 53854);
	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_PORT);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->headerChecksum, be16toh(0x49a2));

	pcpp::DoIpLayer* doipLayer = DiagnosticAckMessage.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	pcpp::DiagnosticAckMessageData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(
		    data.toString(),
		    "source address: 0x4010\ntarget address: 0xe80\nack code: ACK (0x0)\nprevious message: 22f101\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic message Ack");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 8);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Diagnostic message Ack (0x8002)")
}

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

	pcpp::DiagnosticAckMessageData data;
	data.sourceAddress = be16toh(0x4010);
	data.targetAddress = be16toh(0x0e80);
	data.ackCode = pcpp::DoIpDiagnosticAckCodes::ACK;
	// dont use previous message
	data.previousMessage.clear();

	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK, &data);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	// std::cout <<
	// pcpp::byteArrayToHexString(doIpPacket.getRawPacket()->getRawData(),doIpPacket.getRawPacket()->getRawDataLen()) <<
	// std::endl;

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 67);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (67 - 13), bytes, 13);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_POS_ACK, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Diagnostic message Ack");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 5);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Diagnostic message Ack (0x8002)");
}
// ------------------
// DiagnosticNackMessagePacket
PTF_TEST_CASE(DoIpDiagnosticNackMessagePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpDiagnosticNackMessagePacket.dat");

	pcpp::Packet DiagnosticNackMessage(&rawPacket1);
	PTF_ASSERT_TRUE(DiagnosticNackMessage.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(DiagnosticNackMessage.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(DiagnosticNackMessage.isPacketOfType(pcpp::DOIP));

	pcpp::TcpLayer* tcpLayer = DiagnosticNackMessage.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);

	PTF_ASSERT_EQUAL(tcpLayer->getDstPort(), 53854);
	PTF_ASSERT_EQUAL(tcpLayer->getSrcPort(), pcpp::DoIpPorts::TCP_PORT);
	PTF_ASSERT_EQUAL(tcpLayer->getTcpHeader()->headerChecksum, be16toh(0x47a1));

	pcpp::DoIpLayer* doipLayer = DiagnosticNackMessage.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	pcpp::DiagnosticNackMessageData data;
	if (data.buildFromLayer(*doipLayer))
		// std::cout << data.toString();
		PTF_ASSERT_EQUAL(
		    data.toString(),
		    "source address: 0x4010\ntarget address: 0xe80\nnack code: Invalid source address (0x2)\nprevious message: 22f101\n");
	// wrong build

	pcpp::RoutingActivationRequestData routingData;
	PTF_ASSERT_FALSE(routingData.buildFromLayer(*doipLayer));

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Diagnostic message Nack");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 8);
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Diagnostic message Nack (0x8003)")
}

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

	unsigned char bytes[] = { 0x2, 0xfd, 0x80, 0x3, 0x0, 0x0, 0x0, 0x5, 0x40, 0x10, 0xe, 0x80, 0x2 };

	pcpp::DiagnosticNackMessageData data;
	data.sourceAddress = be16toh(0x4010);
	data.targetAddress = be16toh(0x0e80);
	data.nackCode = pcpp::DoIpDiagnosticMessageNackCodes::INVALID_SOURCE_ADDRESS;
	// dont use previous message
	data.previousMessage.clear();

	pcpp::DoIpLayer doipLayer_2(pcpp::DoIpProtocolVersion::Version02Iso2012,
	                            pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK, &data);

	PTF_ASSERT_TRUE(doIpPacket.addLayer(&doipLayer_2));
	doIpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(doIpPacket.getRawPacket()->getRawDataLen(), 67);
	PTF_ASSERT_BUF_COMPARE(doIpPacket.getRawPacket()->getRawData() + (67 - 13), bytes, 13);
	pcpp::DoIpLayer* _doipLayer2 = doIpPacket.getLayerOfType<pcpp::DoIpLayer>();

	PTF_ASSERT_EQUAL(_doipLayer2->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getInvertProtocolVersion(), 0xFD);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadType(), pcpp::DoIpPayloadTypes::DIAGNOSTIC_MESSAGE_NEG_ACK, enumclass);
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadTypeAsStr(), "Diagnostic message Nack");
	PTF_ASSERT_EQUAL(_doipLayer2->getPayloadLength(), 5);
	PTF_ASSERT_EQUAL(_doipLayer2->toString(), "DOIP Layer, Diagnostic message Nack (0x8003)");
}
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

	pcpp::UdpLayer* udpLayer = vehicleIdentificationRequest.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, be16toh(0x8988));
	PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->length, be16toh(0x10));

	// DOIP fields for vehicle identification request
	pcpp::DoIpLayer* doipLayer = vehicleIdentificationRequest.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	// PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012);
	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::DefaultVersion, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0x00);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::VEHICLE_IDENTIFICATION_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Vehicle identification request");
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Vehicle identification request (0x0001)");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x0);

}  // DoIpVehicleIdentificationRequestWithDEfaultVersPacketParsing

// DoIpInvalidPayloadTypePacketPacketParsing
PTF_TEST_CASE(DoIpInvalidPayloadTypePacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/DoIpInvalidPayloadTypePacket.dat");

	pcpp::Packet InvalidPayloadTypePacket(&rawPacket1);
	PTF_ASSERT_TRUE(InvalidPayloadTypePacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(InvalidPayloadTypePacket.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_TRUE(InvalidPayloadTypePacket.isPacketOfType(pcpp::DOIP));

	pcpp::UdpLayer* udpLayer = InvalidPayloadTypePacket.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(udpLayer);

	PTF_ASSERT_EQUAL(udpLayer->getDstPort(), pcpp::DoIpPorts::UDP_PORT);
	PTF_ASSERT_EQUAL(udpLayer->getSrcPort(), 65300);

	// DOIP fields for vehicle identification request
	pcpp::DoIpLayer* doipLayer = InvalidPayloadTypePacket.getLayerOfType<pcpp::DoIpLayer>();
	PTF_ASSERT_NOT_NULL(doipLayer);

	PTF_ASSERT_EQUAL(doipLayer->getProtocolVersion(), pcpp::DoIpProtocolVersion::Version02Iso2012, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getInvertProtocolVersion(), 0xfd);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadType(), pcpp::DoIpPayloadTypes::UNKNOWN_PAYLOAD_TYPE, enumclass);
	PTF_ASSERT_EQUAL(doipLayer->getPayloadTypeAsStr(), "Unknown payload type");
	PTF_ASSERT_EQUAL(doipLayer->toString(), "DOIP Layer, Unknown payload type (0x7777)");
	PTF_ASSERT_EQUAL(doipLayer->getPayloadLength(), 0x0);

}  // DoIpInvalidPayloadTypePacketParsing
DISABLE_WARNING_POP
