#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PPPoELayer.h"
#include "VlanLayer.h"
#include "IcmpLayer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IgmpLayer.h"
#include "DnsLayer.h"
#include "HttpLayer.h"
#include "SSLLayer.h"
#include "RadiusLayer.h"
#include "PacketTrailerLayer.h"
#include "PayloadLayer.h"
#include "GeneralUtils.h"
#include "SystemUtils.h"

PTF_TEST_CASE(InsertDataToPacket)
{
	// Creating a packet
	// ~~~~~~~~~~~~~~~~~

	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

	pcpp::IPv4Address ipSrc("1.1.1.1");
	pcpp::IPv4Address ipDst("20.20.20.20");
	pcpp::IPv4Layer ip4Layer(ipSrc, ipDst);
	ip4Layer.getIPv4Header()->protocol = pcpp::PACKETPP_IPPROTO_TCP;

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	pcpp::PayloadLayer payloadLayer(payload, 10);

	// create the packet
	pcpp::Packet ip4Packet(1);
	PTF_ASSERT_TRUE(ip4Packet.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(ip4Packet.addLayer(&ip4Layer));
	PTF_ASSERT_TRUE(ip4Packet.addLayer(&payloadLayer));

	ip4Packet.computeCalculateFields();

	// Adding a VLAN layer between Eth and IP
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	auto vlanLayer = new pcpp::VlanLayer(100, 0, 0, PCPP_ETHERTYPE_IP);

	PTF_ASSERT_TRUE(ip4Packet.insertLayer(&ethLayer, vlanLayer, true));
	PTF_ASSERT_EQUAL(ethLayer.getDestMac(), dstMac);
	PTF_ASSERT_EQUAL(ip4Layer.getIPv4Header()->internetHeaderLength, 5);
	PTF_ASSERT_EQUAL(ip4Layer.getDstIPAddress(), ipDst);
	PTF_ASSERT_EQUAL(ip4Layer.getSrcIPAddress(), ipSrc);
	PTF_ASSERT_EQUAL(payloadLayer.getPayload()[3], 0x04);

	// Adding another Eth layer at the beginning of the packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::MacAddress srcMac2("cc:cc:cc:cc:cc:cc");
	pcpp::MacAddress dstMac2("dd:dd:dd:dd:dd:dd");
	auto ethLayer2 = new pcpp::EthLayer(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(ip4Packet.insertLayer(nullptr, ethLayer2, true));

	PTF_ASSERT_EQUAL(ip4Packet.getFirstLayer(), ethLayer2, ptr);
	PTF_ASSERT_EQUAL(ip4Packet.getFirstLayer()->getNextLayer(), &ethLayer, ptr);
	PTF_ASSERT_EQUAL(ip4Packet.getFirstLayer()->getNextLayer()->getNextLayer(), vlanLayer, ptr);
	PTF_ASSERT_EQUAL(ethLayer.getDestMac(), dstMac);
	PTF_ASSERT_EQUAL(ip4Layer.getIPv4Header()->internetHeaderLength, 5);
	PTF_ASSERT_EQUAL(ip4Layer.getDstIPAddress(), ipDst);
	PTF_ASSERT_EQUAL(ip4Layer.getSrcIPAddress(), ipSrc);
	PTF_ASSERT_EQUAL(payloadLayer.getPayload()[3], 0x04);

	// Adding a TCP layer at the end of the packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	auto tcpLayer = new pcpp::TcpLayer((uint16_t)12345, (uint16_t)80);
	PTF_ASSERT_TRUE(ip4Packet.insertLayer(&payloadLayer, tcpLayer, true));

	// Create a new packet and use insertLayer for the first layer in packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::EthLayer ethLayer3(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
	pcpp::Packet testPacket(1);
	PTF_ASSERT_TRUE(testPacket.insertLayer(nullptr, &ethLayer3));
	PTF_ASSERT_EQUAL(testPacket.getFirstLayer(), &ethLayer3, ptr);
	PTF_ASSERT_NULL(testPacket.getFirstLayer()->getNextLayer());
	PTF_ASSERT_EQUAL(ethLayer3.getDestMac(), dstMac2);

}  // InsertDataToPacket

PTF_TEST_CASE(CreatePacketFromBuffer)
{
	size_t bufferSize = 46;
	uint8_t* buffer = new uint8_t[bufferSize];
	memset(buffer, 0, bufferSize);

	pcpp::Packet* newPacket = new pcpp::Packet(buffer, bufferSize);

	// Create the packet layers

	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(newPacket->addLayer(&ethLayer));

	pcpp::IPv4Address ipSrc("1.1.1.1");
	pcpp::IPv4Address ipDst("20.20.20.20");
	pcpp::IPv4Layer ip4Layer(ipSrc, ipDst);
	ip4Layer.getIPv4Header()->protocol = pcpp::PACKETPP_IPPROTO_TCP;
	PTF_ASSERT_TRUE(newPacket->addLayer(&ip4Layer));

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	pcpp::PayloadLayer payloadLayer(payload, 10);
	PTF_ASSERT_TRUE(newPacket->addLayer(&payloadLayer));

	pcpp::Logger::getInstance().suppressLogs();

	// Inserting a new layer should fail because the size of the new layer exceeds the buffer size
	pcpp::TcpLayer tcpLayer(12345, 80);
	PTF_ASSERT_FALSE(newPacket->insertLayer(&ip4Layer, &tcpLayer));

	// Extending the IPv4 layer should fail because the size of the new option exceeds the buffer size
	pcpp::IPv4Option newOption = ip4Layer.addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_RouterAlert, (uint16_t)100));
	PTF_ASSERT_TRUE(newOption.isNull());

	pcpp::Logger::getInstance().enableLogs();

	newPacket->computeCalculateFields();

	// Delete the packet - the buffer should not be freed
	delete newPacket;

	std::string expectedHexString =
	    "bbbbbbbbbbbbaaaaaaaaaaaa08004500001e00000000000690b101010101141414140102030405060708090a0000";
	PTF_ASSERT_EQUAL(pcpp::byteArrayToHexString(buffer, bufferSize), expectedHexString);

	delete[] buffer;

}  // CreatePacketFromBuffer

PTF_TEST_CASE(InsertVlanToPacket)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketWithOptions3.dat");

	pcpp::VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);

	pcpp::Packet tcpPacket(&rawPacket1);

	PTF_ASSERT_TRUE(tcpPacket.insertLayer(tcpPacket.getFirstLayer(), &vlanLayer));

	PTF_ASSERT_EQUAL(tcpPacket.getRawPacket()->getRawDataLen(), 78);
	PTF_ASSERT_EQUAL(tcpPacket.getFirstLayer()->getNextLayer(), &vlanLayer, ptr);
	PTF_ASSERT_NOT_NULL(vlanLayer.getNextLayer());
	PTF_ASSERT_EQUAL(vlanLayer.getNextLayer()->getProtocol(), pcpp::IPv4, enum);
}  // InsertVlanToPacket

PTF_TEST_CASE(RemoveLayerTest)
{
	// parse packet and remove layers
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketNoOptions.dat");

	pcpp::Packet tcpPacket(&rawPacket1);

	// a. Remove layer from the middle
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(tcpPacket.removeLayer(pcpp::IPv4));
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(tcpPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NULL(tcpPacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_EQUAL(tcpPacket.getFirstLayer()->getNextLayer()->getProtocol(), pcpp::TCP, enum);
	PTF_ASSERT_EQUAL(tcpPacket.getRawPacket()->getRawDataLen(), 271);

	// b. Remove first layer
	// ~~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(tcpPacket.removeFirstLayer());
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_EQUAL(tcpPacket.getFirstLayer()->getProtocol(), pcpp::TCP, enum);
	PTF_ASSERT_NULL(tcpPacket.getFirstLayer()->getNextLayer()->getNextLayer());
	PTF_ASSERT_EQUAL(tcpPacket.getRawPacket()->getRawDataLen(), 257);

	// c. Remove last layer
	// ~~~~~~~~~~~~~~~~~~~~
	PTF_ASSERT_TRUE(tcpPacket.removeLastLayer());
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_EQUAL(tcpPacket.getFirstLayer(), tcpPacket.getLastLayer(), ptr);
	PTF_ASSERT_EQUAL(tcpPacket.getFirstLayer()->getProtocol(), pcpp::TCP, enum);
	PTF_ASSERT_EQUAL(tcpPacket.getRawPacket()->getRawDataLen(), 20);

	// d. Remove a second layer of the same type
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/Vxlan1.dat");

	pcpp::Packet vxlanPacket(&rawPacket2);
	PTF_ASSERT_TRUE(vxlanPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(vxlanPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(vxlanPacket.removeLayer(pcpp::Ethernet, 1));
	PTF_ASSERT_TRUE(vxlanPacket.removeLayer(pcpp::IPv4, 1));
	PTF_ASSERT_TRUE(vxlanPacket.removeLayer(pcpp::ICMP));
	vxlanPacket.computeCalculateFields();
	PTF_ASSERT_TRUE(vxlanPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(vxlanPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(vxlanPacket.isPacketOfType(pcpp::VXLAN));
	PTF_ASSERT_EQUAL(vxlanPacket.getRawPacket()->getRawDataLen(), 50);

	// e. Remove a layer that doesn't exist
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(vxlanPacket.removeLayer(pcpp::HTTPRequest));
	PTF_ASSERT_FALSE(vxlanPacket.removeLayer(pcpp::Ethernet, 1));
	pcpp::Logger::getInstance().enableLogs();

	// create packet and remove layers
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::Packet testPacket(10);

	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(testPacket.addLayer(&ethLayer));

	pcpp::IPv4Address ipSrc("1.1.1.1");
	pcpp::IPv4Address ipDst("20.20.20.20");
	pcpp::IPv4Layer ip4Layer(ipSrc, ipDst);
	ip4Layer.getIPv4Header()->protocol = pcpp::PACKETPP_IPPROTO_TCP;
	PTF_ASSERT_TRUE(testPacket.addLayer(&ip4Layer));

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	pcpp::PayloadLayer payloadLayer(payload, 10);
	PTF_ASSERT_TRUE(testPacket.addLayer(&payloadLayer));

	// a. remove first layer
	// ~~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(testPacket.removeLayer(pcpp::Ethernet));
	PTF_ASSERT_EQUAL(testPacket.getFirstLayer(), &ip4Layer, ptr);
	PTF_ASSERT_NULL(testPacket.getFirstLayer()->getNextLayer()->getNextLayer());
	PTF_ASSERT_FALSE(testPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(testPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 30);

	// b. remove last layer
	// ~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(testPacket.removeLayer(pcpp::GenericPayload));
	PTF_ASSERT_EQUAL(testPacket.getFirstLayer(), &ip4Layer, ptr);
	PTF_ASSERT_NULL(testPacket.getFirstLayer()->getNextLayer());
	PTF_ASSERT_TRUE(testPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_FALSE(testPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 20);

	// c. insert a layer
	// ~~~~~~~~~~~~~~~~~

	pcpp::VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(testPacket.insertLayer(nullptr, &vlanLayer));
	PTF_ASSERT_EQUAL(testPacket.getFirstLayer(), &vlanLayer, ptr);
	PTF_ASSERT_EQUAL(testPacket.getFirstLayer()->getNextLayer(), &ip4Layer, ptr);
	PTF_ASSERT_TRUE(testPacket.isPacketOfType(pcpp::VLAN));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 24);

	// d. remove the remaining layers (packet remains empty!)
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(testPacket.removeLayer(pcpp::IPv4));
	PTF_ASSERT_EQUAL(testPacket.getFirstLayer(), &vlanLayer, ptr);
	PTF_ASSERT_FALSE(testPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(testPacket.isPacketOfType(pcpp::VLAN));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 4);
	PTF_ASSERT_TRUE(testPacket.removeLayer(pcpp::VLAN));
	PTF_ASSERT_FALSE(testPacket.isPacketOfType(pcpp::VLAN));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 0);

	// Detach layer and add it to another packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// a. create a layer nad a packet and move it to another packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::EthLayer eth(pcpp::MacAddress("0a:00:27:00:00:15"), pcpp::MacAddress("0a:00:27:00:00:16"));
	pcpp::Packet packet1, packet2;
	PTF_ASSERT_TRUE(packet1.addLayer(&eth));
	PTF_ASSERT_EQUAL(packet1.getRawPacket()->getRawDataLen(), 14);
	PTF_ASSERT_TRUE(packet1.detachLayer(&eth));
	PTF_ASSERT_EQUAL(packet1.getRawPacket()->getRawDataLen(), 0);
	PTF_ASSERT_EQUAL(packet2.getRawPacket()->getRawDataLen(), 0);
	PTF_ASSERT_TRUE(packet2.addLayer(&eth));
	PTF_ASSERT_EQUAL(packet2.getRawPacket()->getRawDataLen(), 14);

	// b. parse a packet, detach a layer and move it to another packet
	// c. detach a second instance of the the same protocol
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/Vxlan1.dat");

	pcpp::Packet vxlanPacketOrig(&rawPacket3);
	pcpp::EthLayer* vxlanEthLayer = (pcpp::EthLayer*)vxlanPacketOrig.detachLayer(pcpp::Ethernet, 1);
	pcpp::IcmpLayer* vxlanIcmpLayer = (pcpp::IcmpLayer*)vxlanPacketOrig.detachLayer(pcpp::ICMP);
	pcpp::IPv4Layer* vxlanIP4Layer = (pcpp::IPv4Layer*)vxlanPacketOrig.detachLayer(pcpp::IPv4, 1);
	vxlanPacketOrig.computeCalculateFields();
	PTF_ASSERT_NOT_NULL(vxlanEthLayer);
	PTF_ASSERT_NOT_NULL(vxlanIcmpLayer);
	PTF_ASSERT_NOT_NULL(vxlanIP4Layer);
	PTF_ASSERT_FALSE(vxlanEthLayer->isAllocatedToPacket());
	PTF_ASSERT_FALSE(vxlanIcmpLayer->isAllocatedToPacket());
	PTF_ASSERT_FALSE(vxlanIP4Layer->isAllocatedToPacket());
	PTF_ASSERT_NOT_NULL(vxlanPacketOrig.getLayerOfType(pcpp::Ethernet));
	PTF_ASSERT_NULL(vxlanPacketOrig.getLayerOfType(pcpp::Ethernet, 1));
	PTF_ASSERT_NOT_NULL(vxlanPacketOrig.getLayerOfType(pcpp::IPv4));
	PTF_ASSERT_NULL(vxlanPacketOrig.getLayerOfType(pcpp::IPv4, 1));
	PTF_ASSERT_NULL(vxlanPacketOrig.getLayerOfType(pcpp::ICMP));

	pcpp::Packet packetWithoutTunnel;
	PTF_ASSERT_TRUE(packetWithoutTunnel.addLayer(vxlanEthLayer));
	PTF_ASSERT_TRUE(packetWithoutTunnel.addLayer(vxlanIP4Layer));
	PTF_ASSERT_TRUE(packetWithoutTunnel.addLayer(vxlanIcmpLayer));
	packetWithoutTunnel.computeCalculateFields();

	READ_FILE_INTO_BUFFER(4, "PacketExamples/IcmpWithoutTunnel.dat");

	PTF_ASSERT_EQUAL(packetWithoutTunnel.getRawPacket()->getRawDataLen(), bufferLength4);
	PTF_ASSERT_BUF_COMPARE(packetWithoutTunnel.getRawPacket()->getRawData(), buffer4, bufferLength4);

	delete[] buffer4;

}  // RemoveLayerTest

PTF_TEST_CASE(CopyLayerAndPacketTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TwoHttpResponses1.dat");

	pcpp::Packet sampleHttpPacket(&rawPacket1);

	// RawPacket copy c'tor / assignment operator test
	//-----------------------------------------------
	pcpp::RawPacket copyRawPacket;
	copyRawPacket = rawPacket1;
	PTF_ASSERT_EQUAL(copyRawPacket.getRawDataLen(), rawPacket1.getRawDataLen());
	PTF_ASSERT_TRUE(copyRawPacket.getRawData() != rawPacket1.getRawData());
	PTF_ASSERT_BUF_COMPARE(copyRawPacket.getRawData(), rawPacket1.getRawData(), rawPacket1.getRawDataLen());

	// EthLayer copy c'tor test
	//------------------------
	pcpp::EthLayer ethLayer = *sampleHttpPacket.getLayerOfType<pcpp::EthLayer>();
	PTF_ASSERT_TRUE(sampleHttpPacket.getLayerOfType<pcpp::EthLayer>()->getLayerPayload() != ethLayer.getLayerPayload());
	PTF_ASSERT_BUF_COMPARE(ethLayer.getLayerPayload(),
	                       sampleHttpPacket.getLayerOfType<pcpp::EthLayer>()->getLayerPayload(),
	                       sampleHttpPacket.getLayerOfType<pcpp::EthLayer>()->getLayerPayloadSize());

	// TcpLayer copy c'tor test
	//------------------------
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/TcpPacketWithOptions2.dat");

	pcpp::Packet sampleTcpPacketWithOptions(&rawPacket2);
	pcpp::TcpLayer tcpLayer = *sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_TRUE(sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getData() != tcpLayer.getData());
	PTF_ASSERT_BUF_COMPARE(sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getData(), tcpLayer.getData(),
	                       sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getDataLen());
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(),
	                 sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getTcpOptionCount());
	// clang-format off
	PTF_ASSERT_TRUE(sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getTcpOption(pcpp::TcpOptionEnumType::Timestamp).getRecordBasePtr() != tcpLayer.getTcpOption(pcpp::TcpOptionEnumType::Timestamp).getRecordBasePtr());
	// clang-format on
	PTF_ASSERT_TRUE(
	    sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getTcpOption(pcpp::TcpOptionEnumType::Timestamp) ==
	    tcpLayer.getTcpOption(pcpp::TcpOptionEnumType::Timestamp));

	// HttpLayer copy c'tor test
	//--------------------------

	pcpp::HttpResponseLayer* sampleHttpLayer = sampleHttpPacket.getLayerOfType<pcpp::HttpResponseLayer>();
	pcpp::HttpResponseLayer httpResLayer = *sampleHttpPacket.getLayerOfType<pcpp::HttpResponseLayer>();
	PTF_ASSERT_TRUE(sampleHttpLayer->getFirstLine() != httpResLayer.getFirstLine());
	PTF_ASSERT_EQUAL(sampleHttpLayer->getFirstLine()->getStatusCode(), httpResLayer.getFirstLine()->getStatusCode(),
	                 enum);
	PTF_ASSERT_EQUAL(sampleHttpLayer->getFirstLine()->getSize(), httpResLayer.getFirstLine()->getSize());
	PTF_ASSERT_EQUAL(sampleHttpLayer->getFirstLine()->getVersion(), httpResLayer.getFirstLine()->getVersion(), enum);

	pcpp::HeaderField* curFieldInSample = sampleHttpLayer->getFirstField();
	pcpp::HeaderField* curFieldInCopy = httpResLayer.getFirstField();
	while (curFieldInSample != nullptr && curFieldInCopy != nullptr)
	{
		PTF_ASSERT_TRUE(curFieldInCopy != curFieldInSample);
		PTF_ASSERT_EQUAL(curFieldInSample->getFieldName(), curFieldInCopy->getFieldName());
		PTF_ASSERT_EQUAL(curFieldInSample->getFieldValue(), curFieldInCopy->getFieldValue());
		PTF_ASSERT_EQUAL(curFieldInSample->getFieldSize(), curFieldInCopy->getFieldSize());

		curFieldInSample = sampleHttpLayer->getNextField(curFieldInSample);
		curFieldInCopy = sampleHttpLayer->getNextField(curFieldInCopy);
	}

	PTF_ASSERT_NULL(curFieldInSample);
	PTF_ASSERT_NULL(curFieldInCopy);

	// Packet copy c'tor test - Ethernet
	//---------------------------------

	pcpp::Packet samplePacketCopy(sampleHttpPacket);
	PTF_ASSERT_TRUE(samplePacketCopy.getFirstLayer() != sampleHttpPacket.getFirstLayer());
	PTF_ASSERT_TRUE(samplePacketCopy.getLastLayer() != sampleHttpPacket.getLastLayer());
	PTF_ASSERT_TRUE(samplePacketCopy.getRawPacket() != sampleHttpPacket.getRawPacket());
	PTF_ASSERT_EQUAL(samplePacketCopy.getRawPacket()->getRawDataLen(),
	                 sampleHttpPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(samplePacketCopy.getRawPacket()->getRawData(), sampleHttpPacket.getRawPacket()->getRawData(),
	                       sampleHttpPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_TRUE(samplePacketCopy.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(samplePacketCopy.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(samplePacketCopy.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(samplePacketCopy.isPacketOfType(pcpp::HTTPResponse));
	pcpp::Layer* curSamplePacketLayer = sampleHttpPacket.getFirstLayer();
	pcpp::Layer* curPacketCopyLayer = samplePacketCopy.getFirstLayer();
	while (curSamplePacketLayer != nullptr && curPacketCopyLayer != nullptr)
	{
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getProtocol(), curPacketCopyLayer->getProtocol(), enum);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getHeaderLen(), curPacketCopyLayer->getHeaderLen());
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getLayerPayloadSize(), curPacketCopyLayer->getLayerPayloadSize());
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getDataLen(), curPacketCopyLayer->getDataLen());
		PTF_ASSERT_BUF_COMPARE(curSamplePacketLayer->getData(), curPacketCopyLayer->getData(),
		                       curSamplePacketLayer->getDataLen());
		curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
		curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
	}
	auto samplePacketCopyHttpResponseLayer = samplePacketCopy.getLayerOfType<pcpp::HttpResponseLayer>();
	auto contentTypeField = samplePacketCopyHttpResponseLayer->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
	PTF_ASSERT_NOT_NULL(
	    samplePacketCopyHttpResponseLayer->insertField(contentTypeField, "X-Forwarded-For", "10.20.30.40"));

	samplePacketCopy = sampleHttpPacket;
	samplePacketCopyHttpResponseLayer = samplePacketCopy.getLayerOfType<pcpp::HttpResponseLayer>();
	contentTypeField = samplePacketCopyHttpResponseLayer->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
	PTF_ASSERT_NOT_NULL(
	    samplePacketCopyHttpResponseLayer->insertField(contentTypeField, "X-Forwarded-For", "10.20.30.40"));

	PTF_ASSERT_NULL(curSamplePacketLayer);
	PTF_ASSERT_NULL(curPacketCopyLayer);

	// Packet copy c'tor test - Null/Loopback
	//--------------------------------------

	READ_FILE_AND_CREATE_PACKET_LINKTYPE(3, "PacketExamples/NullLoopback1.dat", pcpp::LINKTYPE_NULL);

	pcpp::Packet nullLoopbackPacket(&rawPacket3);

	pcpp::Packet nullLoopbackPacketCopy(nullLoopbackPacket);

	PTF_ASSERT_TRUE(nullLoopbackPacketCopy.getFirstLayer() != nullLoopbackPacket.getFirstLayer());
	PTF_ASSERT_TRUE(nullLoopbackPacketCopy.getLastLayer() != nullLoopbackPacket.getLastLayer());
	PTF_ASSERT_TRUE(nullLoopbackPacketCopy.getRawPacket() != nullLoopbackPacket.getRawPacket());
	PTF_ASSERT_EQUAL(nullLoopbackPacketCopy.getRawPacket()->getRawDataLen(),
	                 nullLoopbackPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(nullLoopbackPacketCopy.getRawPacket()->getRawData(),
	                       nullLoopbackPacket.getRawPacket()->getRawData(),
	                       nullLoopbackPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_EQUAL(nullLoopbackPacketCopy.getRawPacket()->getLinkLayerType(), pcpp::LINKTYPE_NULL, enum);
	PTF_ASSERT_EQUAL(nullLoopbackPacketCopy.getFirstLayer()->getProtocol(), pcpp::NULL_LOOPBACK, enum);

	curSamplePacketLayer = nullLoopbackPacket.getFirstLayer();
	curPacketCopyLayer = nullLoopbackPacketCopy.getFirstLayer();
	while (curSamplePacketLayer != nullptr && curPacketCopyLayer != nullptr)
	{
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getProtocol(), curPacketCopyLayer->getProtocol(), enum);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getHeaderLen(), curPacketCopyLayer->getHeaderLen());
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getLayerPayloadSize(), curPacketCopyLayer->getLayerPayloadSize());
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getDataLen(), curPacketCopyLayer->getDataLen());
		curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
		curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
	}

	// Packet copy c'tor test - SLL
	//----------------------------

	READ_FILE_AND_CREATE_PACKET_LINKTYPE(4, "PacketExamples/SllPacket2.dat", pcpp::LINKTYPE_LINUX_SLL);

	pcpp::Packet sllPacket(&rawPacket4);

	pcpp::Packet sllPacketCopy(sllPacket);

	PTF_ASSERT_TRUE(sllPacketCopy.getFirstLayer() != sllPacket.getFirstLayer());
	PTF_ASSERT_TRUE(sllPacketCopy.getLastLayer() != sllPacket.getLastLayer());
	PTF_ASSERT_TRUE(sllPacketCopy.getRawPacket() != sllPacket.getRawPacket());
	PTF_ASSERT_EQUAL(sllPacketCopy.getRawPacket()->getRawDataLen(), sllPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(sllPacketCopy.getRawPacket()->getRawData(), sllPacket.getRawPacket()->getRawData(),
	                       sllPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_EQUAL(sllPacketCopy.getRawPacket()->getLinkLayerType(), pcpp::LINKTYPE_LINUX_SLL, enum);
	PTF_ASSERT_EQUAL(sllPacketCopy.getFirstLayer()->getProtocol(), pcpp::SLL, enum);

	curSamplePacketLayer = sllPacket.getFirstLayer();
	curPacketCopyLayer = sllPacketCopy.getFirstLayer();
	while (curSamplePacketLayer != nullptr && curPacketCopyLayer != nullptr)
	{
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getProtocol(), curPacketCopyLayer->getProtocol(), enum);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getHeaderLen(), curPacketCopyLayer->getHeaderLen());
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getLayerPayloadSize(), curPacketCopyLayer->getLayerPayloadSize());
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getDataLen(), curPacketCopyLayer->getDataLen());
		curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
		curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
	}

	// DnsLayer copy c'tor and operator= test
	//--------------------------------------

	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/Dns2.dat");

	pcpp::Packet sampleDnsPacket(&rawPacket5);

	pcpp::DnsLayer* origDnsLayer = sampleDnsPacket.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(origDnsLayer);
	pcpp::DnsLayer copyDnsLayer(*origDnsLayer);
	PTF_ASSERT_EQUAL(copyDnsLayer.getQueryCount(), origDnsLayer->getQueryCount());
	PTF_ASSERT_EQUAL(copyDnsLayer.getFirstQuery()->getName(), origDnsLayer->getFirstQuery()->getName());
	PTF_ASSERT_EQUAL(copyDnsLayer.getFirstQuery()->getDnsType(), origDnsLayer->getFirstQuery()->getDnsType(), enum);

	PTF_ASSERT_EQUAL(copyDnsLayer.getAuthorityCount(), origDnsLayer->getAuthorityCount());
	PTF_ASSERT_EQUAL(copyDnsLayer.getAuthority("Yaels-iPhone.local", true)->getData()->toString(),
	                 origDnsLayer->getAuthority("Yaels-iPhone.local", true)->getData()->toString());

	PTF_ASSERT_EQUAL(copyDnsLayer.getAdditionalRecord("", true)->getData()->toString(),
	                 origDnsLayer->getAdditionalRecord("", true)->getData()->toString());

	copyDnsLayer.addQuery("bla", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_ANY);
	pcpp::IPv4DnsResourceData ipv4DnsData(std::string("1.1.1.1"));
	copyDnsLayer.addAnswer("bla", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_ANY, 123, &ipv4DnsData);

	copyDnsLayer = *origDnsLayer;

	PTF_ASSERT_EQUAL(copyDnsLayer.getQueryCount(), origDnsLayer->getQueryCount());
	PTF_ASSERT_EQUAL(copyDnsLayer.getFirstQuery()->getName(), origDnsLayer->getFirstQuery()->getName());
	PTF_ASSERT_EQUAL(copyDnsLayer.getFirstQuery()->getDnsType(), origDnsLayer->getFirstQuery()->getDnsType(), enum);

	PTF_ASSERT_EQUAL(copyDnsLayer.getAuthorityCount(), origDnsLayer->getAuthorityCount());
	PTF_ASSERT_EQUAL(copyDnsLayer.getAuthority(".local", false)->getData()->toString(),
	                 origDnsLayer->getAuthority("iPhone.local", false)->getData()->toString());

	PTF_ASSERT_EQUAL(copyDnsLayer.getAnswerCount(), origDnsLayer->getAnswerCount());

	PTF_ASSERT_EQUAL(copyDnsLayer.getAdditionalRecord("", true)->getData()->toString(),
	                 origDnsLayer->getAdditionalRecord("", true)->getData()->toString());

}  // CopyLayerAndPacketTest

PTF_TEST_CASE(PacketLayerLookupTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/radius_1.dat");
		pcpp::Packet radiusPacket(&rawPacket1);

		pcpp::RadiusLayer* radiusLayer = radiusPacket.getLayerOfType<pcpp::RadiusLayer>(true);
		PTF_ASSERT_NOT_NULL(radiusLayer);

		pcpp::EthLayer* ethLayer = radiusPacket.getLayerOfType<pcpp::EthLayer>(true);
		PTF_ASSERT_NOT_NULL(ethLayer);

		pcpp::IPv4Layer* ipLayer = radiusPacket.getPrevLayerOfType<pcpp::IPv4Layer>(radiusLayer);
		PTF_ASSERT_NOT_NULL(ipLayer);

		pcpp::TcpLayer* tcpLayer = radiusPacket.getPrevLayerOfType<pcpp::TcpLayer>(ipLayer);
		PTF_ASSERT_NULL(tcpLayer);
	}

	{
		READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/Vxlan1.dat");
		pcpp::Packet vxlanPacket(&rawPacket2);

		// get the last IPv4 layer
		pcpp::IPv4Layer* ipLayer = vxlanPacket.getLayerOfType<pcpp::IPv4Layer>(true);
		PTF_ASSERT_NOT_NULL(ipLayer);
		PTF_ASSERT_EQUAL(ipLayer->getSrcIPAddress(), pcpp::IPv4Address("192.168.203.3"));
		PTF_ASSERT_EQUAL(ipLayer->getDstIPAddress(), pcpp::IPv4Address("192.168.203.5"));

		// get the first IPv4 layer
		ipLayer = vxlanPacket.getPrevLayerOfType<pcpp::IPv4Layer>(ipLayer);
		PTF_ASSERT_NOT_NULL(ipLayer);
		PTF_ASSERT_EQUAL(ipLayer->getSrcIPAddress(), pcpp::IPv4Address("192.168.203.1"));
		PTF_ASSERT_EQUAL(ipLayer->getDstIPAddress(), pcpp::IPv4Address("192.168.202.1"));

		// try to get one more IPv4 layer
		PTF_ASSERT_NULL(vxlanPacket.getPrevLayerOfType<pcpp::IPv4Layer>(ipLayer));

		// get the first layer
		pcpp::EthLayer* ethLayer = vxlanPacket.getPrevLayerOfType<pcpp::EthLayer>(ipLayer);
		PTF_ASSERT_NOT_NULL(ethLayer);
		PTF_ASSERT_NULL(vxlanPacket.getPrevLayerOfType<pcpp::EthLayer>(ethLayer));
		PTF_ASSERT_NULL(vxlanPacket.getPrevLayerOfType<pcpp::EthLayer>(vxlanPacket.getFirstLayer()));

		// try to get nonexistent layer
		PTF_ASSERT_NULL(vxlanPacket.getLayerOfType<pcpp::RadiusLayer>(true));
	}
}  // PacketLayerLookupTest

PTF_TEST_CASE(RawPacketTimeStampSetterTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv6UdpPacket.dat");

	timeval usec_test_time;
	timespec nsec_test_time;
	timespec expected_ts;

	// test usec-precision setter
	usec_test_time.tv_sec = 1583840642;  // 10.03.2020 15:44
	usec_test_time.tv_usec = 111222;
	expected_ts.tv_sec = usec_test_time.tv_sec;
	expected_ts.tv_nsec = usec_test_time.tv_usec * 1000;

	PTF_ASSERT_TRUE(rawPacket1.setPacketTimeStamp(usec_test_time));
	PTF_ASSERT_EQUAL(rawPacket1.getPacketTimeStamp().tv_sec, expected_ts.tv_sec);
	PTF_ASSERT_EQUAL(rawPacket1.getPacketTimeStamp().tv_nsec, expected_ts.tv_nsec);

	// test nsec-precision setter
	nsec_test_time.tv_sec = 1583842105;  // 10.03.2020 16:08
	nsec_test_time.tv_nsec = 111222987;
	expected_ts = nsec_test_time;

	PTF_ASSERT_TRUE(rawPacket1.setPacketTimeStamp(nsec_test_time));
	PTF_ASSERT_EQUAL(rawPacket1.getPacketTimeStamp().tv_sec, expected_ts.tv_sec);
	PTF_ASSERT_EQUAL(rawPacket1.getPacketTimeStamp().tv_nsec, expected_ts.tv_nsec);
}  // RawPacketTimeStampSetterTest

PTF_TEST_CASE(ParsePartialPacketTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/SSL-ClientHello1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IGMPv1_1.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/TwoHttpRequests1.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/PPPoESession2.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/TwoHttpRequests2.dat");
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/IcmpTimestampRequest.dat");
	READ_FILE_AND_CREATE_PACKET(7, "PacketExamples/GREv0_2.dat");

	pcpp::Packet sslPacket(&rawPacket1, pcpp::TCP);
	pcpp::Packet igmpPacket(&rawPacket2, pcpp::IP);
	pcpp::Packet httpPacket(&rawPacket3, pcpp::OsiModelTransportLayer);
	pcpp::Packet pppoePacket(&rawPacket4, pcpp::OsiModelDataLinkLayer);
	pcpp::Packet httpPacket2(&rawPacket5, pcpp::OsiModelPresentationLayer);
	pcpp::Packet icmpPacket(&rawPacket6, pcpp::OsiModelNetworkLayer);
	pcpp::Packet grePacket(&rawPacket7, pcpp::GRE);

	PTF_ASSERT_TRUE(sslPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(sslPacket.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_FALSE(sslPacket.isPacketOfType(pcpp::SSL));
	PTF_ASSERT_NOT_NULL(sslPacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_NOT_NULL(sslPacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_NOT_NULL(sslPacket.getLayerOfType<pcpp::TcpLayer>());
	PTF_ASSERT_NULL(sslPacket.getLayerOfType<pcpp::TcpLayer>()->getNextLayer());
	PTF_ASSERT_NULL(sslPacket.getLayerOfType<pcpp::SSLHandshakeLayer>());
	PTF_ASSERT_NULL(sslPacket.getLayerOfType<pcpp::PayloadLayer>());

	PTF_ASSERT_TRUE(igmpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(igmpPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_FALSE(igmpPacket.isPacketOfType(pcpp::IGMP));
	PTF_ASSERT_NOT_NULL(igmpPacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_NOT_NULL(igmpPacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_NULL(igmpPacket.getLayerOfType<pcpp::IgmpV1Layer>());
	PTF_ASSERT_NULL(igmpPacket.getLayerOfType<pcpp::PayloadLayer>());

	PTF_ASSERT_TRUE(httpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(httpPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(httpPacket.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_FALSE(httpPacket.isPacketOfType(pcpp::HTTP));
	PTF_ASSERT_NOT_NULL(httpPacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_NOT_NULL(httpPacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_NOT_NULL(httpPacket.getLayerOfType<pcpp::TcpLayer>());
	PTF_ASSERT_NULL(httpPacket.getLayerOfType<pcpp::HttpRequestLayer>());
	PTF_ASSERT_NULL(httpPacket.getLayerOfType<pcpp::PayloadLayer>());

	PTF_ASSERT_TRUE(pppoePacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(pppoePacket.isPacketOfType(pcpp::PPPoESession));
	PTF_ASSERT_FALSE(pppoePacket.isPacketOfType(pcpp::IPv6));
	PTF_ASSERT_FALSE(pppoePacket.isPacketOfType(pcpp::UDP));
	PTF_ASSERT_NOT_NULL(pppoePacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_NOT_NULL(pppoePacket.getLayerOfType<pcpp::PPPoESessionLayer>());
	PTF_ASSERT_NULL(pppoePacket.getLayerOfType<pcpp::IPv6Layer>());

	PTF_ASSERT_TRUE(httpPacket2.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(httpPacket2.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(httpPacket2.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_FALSE(httpPacket2.isPacketOfType(pcpp::HTTP));
	PTF_ASSERT_NOT_NULL(httpPacket2.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_NOT_NULL(httpPacket2.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_NOT_NULL(httpPacket2.getLayerOfType<pcpp::TcpLayer>());
	PTF_ASSERT_NULL(httpPacket2.getLayerOfType<pcpp::TcpLayer>()->getNextLayer());
	PTF_ASSERT_EQUAL(httpPacket2.getLastLayer()->getProtocol(), pcpp::TCP, enum);
	PTF_ASSERT_NULL(httpPacket2.getLayerOfType<pcpp::HttpRequestLayer>());
	PTF_ASSERT_NULL(httpPacket2.getLayerOfType<pcpp::PayloadLayer>());

	PTF_ASSERT_TRUE(icmpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(icmpPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(icmpPacket.isPacketOfType(pcpp::ICMP));
	PTF_ASSERT_NOT_NULL(icmpPacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_NOT_NULL(icmpPacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_NOT_NULL(icmpPacket.getLayerOfType<pcpp::IcmpLayer>());

	PTF_ASSERT_TRUE(grePacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(grePacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(grePacket.isPacketOfType(pcpp::GREv0));
	PTF_ASSERT_FALSE(grePacket.isPacketOfType(pcpp::UDP));
	pcpp::Layer* curLayer = grePacket.getFirstLayer();
	PTF_ASSERT_NOT_NULL(curLayer);
	PTF_ASSERT_EQUAL(curLayer->getProtocol(), pcpp::Ethernet, enum);
	curLayer = curLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(curLayer);
	PTF_ASSERT_EQUAL(curLayer->getProtocol(), pcpp::IPv4, enum);
	curLayer = curLayer->getNextLayer();
	PTF_ASSERT_NOT_NULL(curLayer);
	PTF_ASSERT_EQUAL(curLayer->getProtocol(), pcpp::GREv0, enum);
	curLayer = curLayer->getNextLayer();
	PTF_ASSERT_NULL(curLayer);
}  // ParsePartialPacketTest

PTF_TEST_CASE(PacketTrailerTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/packet_trailer_arp.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/packet_trailer_ipv4.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/packet_trailer_ipv6.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/packet_trailer_pppoed.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/packet_trailer_ipv6.dat");

	pcpp::Packet trailerArpPacket(&rawPacket1);
	pcpp::Packet trailerIPv4Packet(&rawPacket2);
	pcpp::Packet trailerIPv6Packet(&rawPacket3);
	pcpp::Packet trailerPPPoEDPacket(&rawPacket4);
	pcpp::Packet trailerIPv6Packet2(&rawPacket5);

	PTF_ASSERT_TRUE(trailerArpPacket.isPacketOfType(pcpp::PacketTrailer));
	PTF_ASSERT_TRUE(trailerIPv4Packet.isPacketOfType(pcpp::PacketTrailer));
	PTF_ASSERT_TRUE(trailerIPv6Packet.isPacketOfType(pcpp::PacketTrailer));
	PTF_ASSERT_TRUE(trailerPPPoEDPacket.isPacketOfType(pcpp::PacketTrailer));

	PTF_ASSERT_EQUAL(trailerArpPacket.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerLen(), 18);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerLen(), 6);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerLen(), 4);
	PTF_ASSERT_EQUAL(trailerPPPoEDPacket.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerLen(), 28);

	PTF_ASSERT_EQUAL(trailerArpPacket.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerDataAsHexString(),
	                 "742066726f6d2062726964676500203d3d20");
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerDataAsHexString(),
	                 "0101080a0000");
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerDataAsHexString(),
	                 "cdfcf105");
	PTF_ASSERT_EQUAL(trailerPPPoEDPacket.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerDataAsHexString(),
	                 "00000000000000000000000000000000000000000000000000000000");

	PTF_ASSERT_EQUAL(trailerArpPacket.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerData()[3], 0x72, hex);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerData()[2], 0x8, hex);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerData()[1], 0xfc, hex);
	PTF_ASSERT_EQUAL(trailerPPPoEDPacket.getLayerOfType<pcpp::PacketTrailerLayer>()->getTrailerData()[12], 0, hex);

	pcpp::EthLayer* ethLayer = trailerIPv4Packet.getLayerOfType<pcpp::EthLayer>();
	pcpp::IPv4Layer* ip4Layer = trailerIPv4Packet.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ethLayer);
	PTF_ASSERT_NOT_NULL(ip4Layer);
	PTF_ASSERT_GREATER_THAN(ethLayer->getDataLen() - ethLayer->getHeaderLen(), ip4Layer->getDataLen());
	PTF_ASSERT_EQUAL(ip4Layer->getDataLen(), be16toh(ip4Layer->getIPv4Header()->totalLength));

	ethLayer = trailerIPv6Packet.getLayerOfType<pcpp::EthLayer>();
	pcpp::IPv6Layer* ip6Layer = trailerIPv6Packet.getLayerOfType<pcpp::IPv6Layer>();
	PTF_ASSERT_NOT_NULL(ethLayer);
	PTF_ASSERT_NOT_NULL(ip6Layer);
	PTF_ASSERT_GREATER_THAN(ethLayer->getDataLen() - ethLayer->getHeaderLen(), ip6Layer->getDataLen());
	PTF_ASSERT_EQUAL(ip6Layer->getDataLen(),
	                 be16toh(ip6Layer->getIPv6Header()->payloadLength) + ip6Layer->getHeaderLen());

	// add layer before trailer
	auto newVlanLayer = new pcpp::VlanLayer(123, true, 1, PCPP_ETHERTYPE_IPV6);
	PTF_ASSERT_TRUE(trailerIPv6Packet.insertLayer(ethLayer, newVlanLayer, true));
	trailerIPv6Packet.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 468);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::VlanLayer>()->getDataLen(), 454);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::IPv6Layer>()->getDataLen(), 446);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::UdpLayer>()->getDataLen(), 406);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::DnsLayer>()->getDataLen(), 398);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 4);

	// add layer just before trailer
	auto httpReq = new pcpp::HttpRequestLayer(pcpp::HttpRequestLayer::HttpGET, "/main.html", pcpp::OneDotOne);
	httpReq->addEndOfHeader();
	pcpp::TcpLayer* tcpLayer = trailerIPv4Packet.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_NOT_NULL(tcpLayer);
	trailerIPv4Packet.insertLayer(tcpLayer, httpReq, true);
	trailerIPv4Packet.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 87);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::IPv4Layer>()->getDataLen(), 67);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::TcpLayer>()->getDataLen(), 47);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::HttpRequestLayer>()->getDataLen(), 27);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 6);

	// add layer after trailer (result with an error)
	uint8_t payload[4] = { 0x1, 0x2, 0x3, 0x4 };
	std::unique_ptr<pcpp::PayloadLayer> newPayloadLayer = std::make_unique<pcpp::PayloadLayer>(payload, 4);
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(trailerIPv4Packet.addLayer(newPayloadLayer.get(), true));
	pcpp::Logger::getInstance().enableLogs();

	// remove layer before trailer
	PTF_ASSERT_TRUE(trailerIPv4Packet.removeLayer(pcpp::TCP));
	trailerIPv4Packet.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 67);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::IPv4Layer>()->getDataLen(), 47);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::HttpRequestLayer>()->getDataLen(), 27);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 6);

	// remove layer just before trailer
	PTF_ASSERT_TRUE(trailerIPv4Packet.removeLayer(pcpp::HTTPRequest));
	trailerIPv4Packet.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 40);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::IPv4Layer>()->getDataLen(), 20);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 6);

	// remove trailer
	ethLayer = trailerIPv6Packet2.getLayerOfType<pcpp::EthLayer>();
	auto newVlanLayer2 = new pcpp::VlanLayer(456, true, 1, PCPP_ETHERTYPE_IPV6);
	PTF_ASSERT_TRUE(trailerIPv6Packet2.insertLayer(ethLayer, newVlanLayer2, true));
	pcpp::PacketTrailerLayer* packetTrailer = trailerIPv6Packet2.getLayerOfType<pcpp::PacketTrailerLayer>();
	PTF_ASSERT_NOT_NULL(packetTrailer);
	PTF_ASSERT_TRUE(trailerIPv6Packet2.removeLayer(pcpp::PacketTrailer));
	trailerIPv6Packet2.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerIPv6Packet2.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 464);
	PTF_ASSERT_EQUAL(trailerIPv6Packet2.getLayerOfType<pcpp::VlanLayer>()->getDataLen(), 450);
	PTF_ASSERT_EQUAL(trailerIPv6Packet2.getLayerOfType<pcpp::IPv6Layer>()->getDataLen(), 446);
	PTF_ASSERT_EQUAL(trailerIPv6Packet2.getLayerOfType<pcpp::UdpLayer>()->getDataLen(), 406);
	PTF_ASSERT_EQUAL(trailerIPv6Packet2.getLayerOfType<pcpp::DnsLayer>()->getDataLen(), 398);

	// remove all layers but the trailer
	PTF_ASSERT_TRUE(trailerIPv4Packet.removeLayer(pcpp::Ethernet));
	trailerIPv4Packet.computeCalculateFields();
	PTF_ASSERT_TRUE(trailerIPv4Packet.removeLayer(pcpp::IPv4));
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 6);

	// rebuild packet starting from trailer
	auto newEthLayer = new pcpp::EthLayer(pcpp::MacAddress("30:46:9a:23:fb:fa"), pcpp::MacAddress("6c:f0:49:b2:de:6e"),
	                                      PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(trailerIPv4Packet.insertLayer(nullptr, newEthLayer, true));
	auto newIp4Layer = new pcpp::IPv4Layer(pcpp::IPv4Address("173.194.78.104"), pcpp::IPv4Address("10.0.0.1"));
	newIp4Layer->getIPv4Header()->ipId = htobe16(40382);
	newIp4Layer->getIPv4Header()->timeToLive = 46;
	trailerIPv4Packet.insertLayer(newEthLayer, newIp4Layer, true);
	auto newTcpLayer = new pcpp::TcpLayer(443, 55194);
	newTcpLayer->getTcpHeader()->ackNumber = htobe32(0x807df56c);
	newTcpLayer->getTcpHeader()->sequenceNumber = htobe32(0x46529f28);
	newTcpLayer->getTcpHeader()->ackFlag = 1;
	newTcpLayer->getTcpHeader()->windowSize = htobe16(344);
	trailerIPv4Packet.insertLayer(newIp4Layer, newTcpLayer, true);
	trailerIPv4Packet.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 60);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::IPv4Layer>()->getDataLen(), 40);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::TcpLayer>()->getDataLen(), 20);
	PTF_ASSERT_EQUAL(trailerIPv4Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 6);

	// extend layer before trailer
	ip6Layer = trailerIPv6Packet.getLayerOfType<pcpp::IPv6Layer>();
	pcpp::IPv6RoutingHeader routingExt(4, 3, nullptr, 0);
	ip6Layer->addExtension<pcpp::IPv6RoutingHeader>(routingExt);
	trailerIPv6Packet.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 476);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::VlanLayer>()->getDataLen(), 462);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::IPv6Layer>()->getDataLen(), 454);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::UdpLayer>()->getDataLen(), 406);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::DnsLayer>()->getDataLen(), 398);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 4);

	// extend layer just before trailer
	pcpp::PPPoEDiscoveryLayer* pppoeDiscovery = trailerPPPoEDPacket.getLayerOfType<pcpp::PPPoEDiscoveryLayer>();
	PTF_ASSERT_NOT_NULL(pppoeDiscovery);
	// clang-format off
	PTF_ASSERT_FALSE(pppoeDiscovery->addTag(pcpp::PPPoEDiscoveryLayer::PPPoETagBuilder(pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME, 0x42524153)).isNull());
	// clang-format on
	trailerPPPoEDPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerPPPoEDPacket.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 68);
	PTF_ASSERT_EQUAL(trailerPPPoEDPacket.getLayerOfType<pcpp::PPPoEDiscoveryLayer>()->getDataLen(), 26);
	PTF_ASSERT_EQUAL(trailerPPPoEDPacket.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 28);

	// shorten layer before trailer
	ip6Layer = trailerIPv6Packet.getLayerOfType<pcpp::IPv6Layer>();
	ip6Layer->removeAllExtensions();
	trailerIPv6Packet.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 468);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::VlanLayer>()->getDataLen(), 454);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::IPv6Layer>()->getDataLen(), 446);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::UdpLayer>()->getDataLen(), 406);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::DnsLayer>()->getDataLen(), 398);
	PTF_ASSERT_EQUAL(trailerIPv6Packet.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 4);

	// shorten layer just before trailer
	pppoeDiscovery = trailerPPPoEDPacket.getLayerOfType<pcpp::PPPoEDiscoveryLayer>();
	PTF_ASSERT_TRUE(pppoeDiscovery->removeAllTags());
	trailerPPPoEDPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(trailerPPPoEDPacket.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 48);
	PTF_ASSERT_EQUAL(trailerPPPoEDPacket.getLayerOfType<pcpp::PPPoEDiscoveryLayer>()->getDataLen(), 6);
	PTF_ASSERT_EQUAL(trailerPPPoEDPacket.getLayerOfType<pcpp::PacketTrailerLayer>()->getDataLen(), 28);
}  // PacketTrailerTest

PTF_TEST_CASE(ResizeLayerTest)
{
	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	pcpp::PayloadLayer payloadLayer(payload, 10);

	// Creating a packet
	pcpp::Packet packet(1500);
	PTF_ASSERT_TRUE(packet.addLayer(&payloadLayer));

	// Starting Resize testing
	PTF_ASSERT_EQUAL(packet.getRawPacket()->getRawDataLen(), 10);  // Size of packet before resizing is not correct

	//
	// test shortening of packet and layer
	//
	uint8_t payload2[] = { 0x05, 0x04, 0x03, 0x02, 0x01 };
	size_t payload2_size = 5;
	payloadLayer.setPayload(payload2, payload2_size);

	// check that resizing worked in terms of data length
	PTF_ASSERT_EQUAL(packet.getRawPacket()->getRawDataLen(),
	                 (int)payload2_size);  // Size of packet after first resizing (shortening) is not correct

	// confirm that data has been correctly written to raw packet
	const uint8_t* rawData =
	    packet.getRawPacket()->getRawData() + (packet.getRawPacket()->getRawDataLen() - payload2_size);
	PTF_ASSERT_EQUAL(rawData[0], 0x05);  // Setting payload to new payload has failed.
	PTF_ASSERT_EQUAL(rawData[1], 0x04);
	PTF_ASSERT_EQUAL(rawData[2], 0x03);
	PTF_ASSERT_EQUAL(rawData[3], 0x02);
	PTF_ASSERT_EQUAL(rawData[4], 0x01);

	//
	// test extension of packet and layer
	//
	uint8_t payload3[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
	size_t payload3_size = 8;
	payloadLayer.setPayload(payload3, payload3_size);

	// check that resizing worked in terms of data length
	PTF_ASSERT_EQUAL(packet.getRawPacket()->getRawDataLen(),
	                 (int)payload3_size);  // Size of packet after second resizing (extension) is not correct

	// confirm that data has been correctly written to raw packet
	const uint8_t* rawData2 =
	    packet.getRawPacket()->getRawData() + (packet.getRawPacket()->getRawDataLen() - payload3_size);
	PTF_ASSERT_EQUAL(rawData2[0], 0xDE);  // Setting payload to new payload has failed.
	PTF_ASSERT_EQUAL(rawData2[1], 0xAD);
	PTF_ASSERT_EQUAL(rawData2[2], 0xBE);
	PTF_ASSERT_EQUAL(rawData2[3], 0xEF);
	PTF_ASSERT_EQUAL(rawData2[4], 0xDE);
	PTF_ASSERT_EQUAL(rawData2[5], 0xAD);
	PTF_ASSERT_EQUAL(rawData2[6], 0xBE);
	PTF_ASSERT_EQUAL(rawData2[7], 0xEF);
}  // ResizeLayerTest

PTF_TEST_CASE(PrintPacketAndLayersTest)
{
	timeval time;
	time.tv_sec = 1634026009;
	time.tv_usec = 0;

	// convert the timestamp to a printable format
	time_t nowtime = time.tv_sec;
	struct tm* nowtm = nullptr;
#if __cplusplus > 199711L && !defined(_WIN32)
	// localtime_r is a thread-safe versions of localtime,
	// but they're defined only in newer compilers (>= C++0x).
	// on Windows localtime is already thread-safe so there is not need
	// to use localtime_r
	struct tm nowtm_r;
	nowtm = localtime_r(&nowtime, &nowtm_r);
#else
	// on Window compilers localtime is already thread safe.
	// in old compilers (< C++0x) localtime_r was not defined so we have to fall back to localtime
	nowtm = localtime(&nowtime);
#endif

	char tmbuf[64];
	strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/MplsPackets1.dat");
	pcpp::Packet packet(&rawPacket1);

	std::string expectedPacketHeaderString =
	    "Packet length: 361 [Bytes], Arrival time: " + std::string(tmbuf) + ".000000000";
	std::vector<std::string> expectedLayerStrings;
	expectedLayerStrings.push_back("Ethernet II Layer, Src: 50:81:89:f9:d5:7b, Dst: 28:c2:ce:ba:97:e8");
	expectedLayerStrings.push_back("VLAN Layer, Priority: 0, Vlan ID: 215, CFI: 0");
	expectedLayerStrings.push_back("VLAN Layer, Priority: 0, Vlan ID: 11, CFI: 0");
	expectedLayerStrings.push_back("MPLS Layer, Label: 16000, Exp: 0, TTL: 126, Bottom of stack: true");
	expectedLayerStrings.push_back("IPv4 Layer, Src: 2.3.4.6, Dst: 12.13.14.15");
	expectedLayerStrings.push_back("TCP Layer, [ACK], Src port: 20636, Dst port: 80");
	expectedLayerStrings.push_back("HTTP request, GET /i/?tid=199&hash=8ktxrl&subid=0 HTTP/1.1");

	// test print layers
	std::vector<std::string>::iterator iter = expectedLayerStrings.begin();
	for (pcpp::Layer* layer = packet.getFirstLayer(); layer != nullptr; layer = layer->getNextLayer())
	{
		PTF_ASSERT_EQUAL(layer->toString(), *iter);
		std::ostringstream layerStream;
		layerStream << *layer;
		PTF_ASSERT_EQUAL(layerStream.str(), *iter);
		++iter;
	}
	PTF_ASSERT_TRUE(iter == expectedLayerStrings.end());

	// test print packet
	std::ostringstream expectedStream;
	expectedStream << expectedPacketHeaderString << std::endl;
	for (const auto& it : expectedLayerStrings)
	{
		expectedStream << it << std::endl;
	}

	std::ostringstream packetStream;
	packetStream << packet;
	PTF_ASSERT_EQUAL(packetStream.str(), expectedStream.str());
	PTF_ASSERT_EQUAL(packet.toString(), expectedStream.str());

	expectedLayerStrings.insert(expectedLayerStrings.begin(), expectedPacketHeaderString);
	std::vector<std::string> packetAsStringList;
	packet.toStringList(packetAsStringList);
	PTF_ASSERT_TRUE(packetAsStringList == expectedLayerStrings);
}  // PrintPacketAndLayer

PTF_TEST_CASE(ProtocolFamilyMembershipTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TwoHttpRequests1.dat");

	pcpp::Packet packet(&rawPacket1);

	auto ipV4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_TRUE(ipV4Layer->isMemberOfProtocolFamily(pcpp::IP));
	PTF_ASSERT_TRUE(ipV4Layer->isMemberOfProtocolFamily(pcpp::IPv4));
	PTF_ASSERT_FALSE(ipV4Layer->isMemberOfProtocolFamily(pcpp::IPv6));
	PTF_ASSERT_FALSE(ipV4Layer->isMemberOfProtocolFamily(pcpp::HTTP));

	auto httpLayer = packet.getLayerOfType<pcpp::HttpRequestLayer>();
	PTF_ASSERT_TRUE(httpLayer->isMemberOfProtocolFamily(pcpp::HTTP));
	PTF_ASSERT_TRUE(httpLayer->isMemberOfProtocolFamily(pcpp::HTTPRequest));
	PTF_ASSERT_FALSE(httpLayer->isMemberOfProtocolFamily(pcpp::HTTPResponse));
	PTF_ASSERT_FALSE(httpLayer->isMemberOfProtocolFamily(pcpp::IP));
}

PTF_TEST_CASE(PacketParseLayerLimitTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(0, "PacketExamples/TcpPacketWithOptions3.dat");
	pcpp::Packet packet0(&rawPacket0, pcpp::OsiModelPhysicalLayer);
	PTF_ASSERT_EQUAL(packet0.getLastLayer(), packet0.getFirstLayer());

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketWithOptions3.dat");
	pcpp::Packet packet1(&rawPacket1, pcpp::OsiModelTransportLayer);
	PTF_ASSERT_EQUAL(packet1.getLastLayer()->getOsiModelLayer(), pcpp::OsiModelTransportLayer);
}
