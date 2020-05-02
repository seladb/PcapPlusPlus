#include "../Utils/TestUtils.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PPPoELayer.h"
#include "VlanLayer.h"
#include "IcmpLayer.h"
#include "TcpLayer.h"
#include "IgmpLayer.h"
#include "DnsLayer.h"
#include "HttpLayer.h"
#include "SSLLayer.h"
#include "RadiusLayer.h"
#include "PayloadLayer.h"
#include "../TestDefinition.h"
#include "SystemUtils.h"

PTF_TEST_CASE(InsertDataToPacket)
{
	// Creating a packet
	// ~~~~~~~~~~~~~~~~~

	pcpp::Packet ip4Packet(1);

	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(ip4Packet.addLayer(&ethLayer));

	pcpp::IPv4Address ipSrc(std::string("1.1.1.1"));
	pcpp::IPv4Address ipDst(std::string("20.20.20.20"));
	pcpp::IPv4Layer ip4Layer(ipSrc, ipDst);
	ip4Layer.getIPv4Header()->protocol = pcpp::PACKETPP_IPPROTO_TCP;
	PTF_ASSERT_TRUE(ip4Packet.addLayer(&ip4Layer));

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	pcpp::PayloadLayer payloadLayer(payload, 10, true);
	PTF_ASSERT_TRUE(ip4Packet.addLayer(&payloadLayer));

	ip4Packet.computeCalculateFields();

	// Adding a VLAN layer between Eth and IP
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::VlanLayer vlanLayer(100, 0, 0, PCPP_ETHERTYPE_IP);

	PTF_ASSERT_TRUE(ip4Packet.insertLayer(&ethLayer, &vlanLayer));
	PTF_ASSERT_EQUAL(ethLayer.getDestMac(), dstMac, object);
	PTF_ASSERT_EQUAL(ip4Layer.getIPv4Header()->internetHeaderLength, 5, u8);
	PTF_ASSERT_EQUAL(ip4Layer.getDstIpAddress(), ipDst, object);
	PTF_ASSERT_EQUAL(ip4Layer.getSrcIpAddress(), ipSrc, object);
	PTF_ASSERT_EQUAL(payloadLayer.getPayload()[3], 0x04, u8);


	// Adding another Eth layer at the beginning of the packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::MacAddress srcMac2("cc:cc:cc:cc:cc:cc");
	pcpp::MacAddress dstMac2("dd:dd:dd:dd:dd:dd");
	pcpp::EthLayer ethLayer2(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(ip4Packet.insertLayer(NULL, &ethLayer2));

	PTF_ASSERT_TRUE(ip4Packet.getFirstLayer() == &ethLayer2);
	PTF_ASSERT_TRUE(ip4Packet.getFirstLayer()->getNextLayer() == &ethLayer);
	PTF_ASSERT_TRUE(ip4Packet.getFirstLayer()->getNextLayer()->getNextLayer() == &vlanLayer);
	PTF_ASSERT_EQUAL(ethLayer.getDestMac(), dstMac, object);
	PTF_ASSERT_EQUAL(ip4Layer.getIPv4Header()->internetHeaderLength, 5, u8);
	PTF_ASSERT_EQUAL(ip4Layer.getDstIpAddress(), ipDst, object);
	PTF_ASSERT_EQUAL(ip4Layer.getSrcIpAddress(), ipSrc, object);
	PTF_ASSERT_EQUAL(payloadLayer.getPayload()[3], 0x04, u8);


	// Adding a TCP layer at the end of the packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::TcpLayer tcpLayer((uint16_t)12345, (uint16_t)80);
	PTF_ASSERT_TRUE(ip4Packet.insertLayer(&payloadLayer, &tcpLayer));


	// Create a new packet and use insertLayer for the first layer in packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::Packet testPacket(1);
	pcpp::EthLayer ethLayer3(srcMac2, dstMac2, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(testPacket.insertLayer(NULL, &ethLayer3));
	PTF_ASSERT_TRUE(testPacket.getFirstLayer() == &ethLayer3);
	PTF_ASSERT_NULL(testPacket.getFirstLayer()->getNextLayer());
	PTF_ASSERT_EQUAL(ethLayer3.getDestMac(), dstMac2, object);

} // InsertDataToPacket



PTF_TEST_CASE(InsertVlanToPacket)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketWithOptions3.dat");

	pcpp::Packet tcpPacket(&rawPacket1);

	pcpp::VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(tcpPacket.insertLayer(tcpPacket.getFirstLayer(), &vlanLayer));

	PTF_ASSERT_EQUAL(tcpPacket.getRawPacket()->getRawDataLen(), 78, int);
	PTF_ASSERT_TRUE(tcpPacket.getFirstLayer()->getNextLayer() == &vlanLayer);
	PTF_ASSERT_NOT_NULL(vlanLayer.getNextLayer());
	PTF_ASSERT_EQUAL(vlanLayer.getNextLayer()->getProtocol(), pcpp::IPv4, u64);
} // InsertVlanToPacket



PTF_TEST_CASE(RemoveLayerTest)
{
	// parse packet and remove layers
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TcpPacketNoOptions.dat");

	pcpp::Packet tcpPacket(&rawPacket1);


	// a. Remove layer from the middle
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(tcpPacket.removeLayer(pcpp::IPv4));
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(tcpPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NULL(tcpPacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_EQUAL(tcpPacket.getFirstLayer()->getNextLayer()->getProtocol(), pcpp::TCP, u64);
	PTF_ASSERT_EQUAL(tcpPacket.getRawPacket()->getRawDataLen(), 271, int);


	// b. Remove first layer
	// ~~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(tcpPacket.removeFirstLayer());
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_EQUAL(tcpPacket.getFirstLayer()->getProtocol(), pcpp::TCP, u64);
	PTF_ASSERT_NULL(tcpPacket.getFirstLayer()->getNextLayer()->getNextLayer());
	PTF_ASSERT_EQUAL(tcpPacket.getRawPacket()->getRawDataLen(), 257, int);


	// c. Remove last layer
	// ~~~~~~~~~~~~~~~~~~~~
	PTF_ASSERT_TRUE(tcpPacket.removeLastLayer());
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_FALSE(tcpPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(tcpPacket.getFirstLayer() == tcpPacket.getLastLayer());
	PTF_ASSERT_EQUAL(tcpPacket.getFirstLayer()->getProtocol(), pcpp::TCP, u64);
	PTF_ASSERT_EQUAL(tcpPacket.getRawPacket()->getRawDataLen(), 20, int);


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
	PTF_ASSERT_EQUAL(vxlanPacket.getRawPacket()->getRawDataLen(), 50, int);


	// e. Remove a layer that doesn't exist
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_FALSE(vxlanPacket.removeLayer(pcpp::HTTPRequest));
	PTF_ASSERT_FALSE(vxlanPacket.removeLayer(pcpp::Ethernet, 1));
	pcpp::LoggerPP::getInstance().enableErrors();


	// create packet and remove layers
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::Packet testPacket(10);

	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(testPacket.addLayer(&ethLayer));

	pcpp::IPv4Address ipSrc(std::string("1.1.1.1"));
	pcpp::IPv4Address ipDst(std::string("20.20.20.20"));
	pcpp::IPv4Layer ip4Layer(ipSrc, ipDst);
	ip4Layer.getIPv4Header()->protocol = pcpp::PACKETPP_IPPROTO_TCP;
	PTF_ASSERT_TRUE(testPacket.addLayer(&ip4Layer));

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	pcpp::PayloadLayer payloadLayer(payload, 10, true);
	PTF_ASSERT_TRUE(testPacket.addLayer(&payloadLayer));


	// a. remove first layer
	// ~~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(testPacket.removeLayer(pcpp::Ethernet));
	PTF_ASSERT_TRUE(testPacket.getFirstLayer() == &ip4Layer);
	PTF_ASSERT_NULL(testPacket.getFirstLayer()->getNextLayer()->getNextLayer());
	PTF_ASSERT_FALSE(testPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(testPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 30, int);


	// b. remove last layer
	// ~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(testPacket.removeLayer(pcpp::GenericPayload));
	PTF_ASSERT_TRUE(testPacket.getFirstLayer() == &ip4Layer);
	PTF_ASSERT_NULL(testPacket.getFirstLayer()->getNextLayer());
	PTF_ASSERT_TRUE(testPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_FALSE(testPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 20, int);


	// c. insert a layer
	// ~~~~~~~~~~~~~~~~~

	pcpp::VlanLayer vlanLayer(4001, 0, 0, PCPP_ETHERTYPE_IP);
	PTF_ASSERT_TRUE(testPacket.insertLayer(NULL, &vlanLayer));
	PTF_ASSERT_TRUE(testPacket.getFirstLayer() == &vlanLayer);
	PTF_ASSERT_TRUE(testPacket.getFirstLayer()->getNextLayer() == &ip4Layer);
	PTF_ASSERT_TRUE(testPacket.isPacketOfType(pcpp::VLAN));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 24, int);


	// d. remove the remaining layers (packet remains empty!)
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	PTF_ASSERT_TRUE(testPacket.removeLayer(pcpp::IPv4));
	PTF_ASSERT_TRUE(testPacket.getFirstLayer() == &vlanLayer);
	PTF_ASSERT_FALSE(testPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(testPacket.isPacketOfType(pcpp::VLAN));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 4, int);
	PTF_ASSERT_TRUE(testPacket.removeLayer(pcpp::VLAN));
	PTF_ASSERT_FALSE(testPacket.isPacketOfType(pcpp::VLAN));
	PTF_ASSERT_EQUAL(testPacket.getRawPacket()->getRawDataLen(), 0, int);


	// Detach layer and add it to another packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// a. create a layer nad a packet and move it to another packet
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	pcpp::EthLayer eth(pcpp::MacAddress("0a:00:27:00:00:15"), pcpp::MacAddress("0a:00:27:00:00:16"));
	pcpp::Packet packet1, packet2;
	PTF_ASSERT_TRUE(packet1.addLayer(&eth));
	PTF_ASSERT_EQUAL(packet1.getRawPacket()->getRawDataLen(), 14, int);
	PTF_ASSERT_TRUE(packet1.detachLayer(&eth));
	PTF_ASSERT_EQUAL(packet1.getRawPacket()->getRawDataLen(), 0, int);
	PTF_ASSERT_EQUAL(packet2.getRawPacket()->getRawDataLen(), 0, int);
	PTF_ASSERT_TRUE(packet2.addLayer(&eth));
	PTF_ASSERT_EQUAL(packet2.getRawPacket()->getRawDataLen(), 14, int);

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

	PTF_ASSERT_EQUAL(packetWithoutTunnel.getRawPacket()->getRawDataLen(), bufferLength4, int);
  PTF_ASSERT_BUF_COMPARE(packetWithoutTunnel.getRawPacket()->getRawData(), buffer4, bufferLength4);

	delete [] buffer4;

} // RemoveLayerTest


PTF_TEST_CASE(CopyLayerAndPacketTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TwoHttpResponses1.dat");

	pcpp::Packet sampleHttpPacket(&rawPacket1);

	//RawPacket copy c'tor / assignment operator test
	//-----------------------------------------------
	pcpp::RawPacket copyRawPacket;
	copyRawPacket = rawPacket1;
	PTF_ASSERT_EQUAL(copyRawPacket.getRawDataLen(), rawPacket1.getRawDataLen(), int);
	PTF_ASSERT_TRUE(copyRawPacket.getRawData() != rawPacket1.getRawData());
	PTF_ASSERT_BUF_COMPARE(copyRawPacket.getRawData(), rawPacket1.getRawData(), rawPacket1.getRawDataLen());

	//EthLayer copy c'tor test
	//------------------------
	pcpp::EthLayer ethLayer = *sampleHttpPacket.getLayerOfType<pcpp::EthLayer>();
	PTF_ASSERT_TRUE(sampleHttpPacket.getLayerOfType<pcpp::EthLayer>()->getLayerPayload() != ethLayer.getLayerPayload());
	PTF_ASSERT_BUF_COMPARE(ethLayer.getLayerPayload(), sampleHttpPacket.getLayerOfType<pcpp::EthLayer>()->getLayerPayload(), sampleHttpPacket.getLayerOfType<pcpp::EthLayer>()->getLayerPayloadSize());


	//TcpLayer copy c'tor test
	//------------------------
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/TcpPacketWithOptions2.dat");

	pcpp::Packet sampleTcpPacketWithOptions(&rawPacket2);
	pcpp::TcpLayer tcpLayer = *sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>();
	PTF_ASSERT_TRUE(sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getData() != tcpLayer.getData());
	PTF_ASSERT_BUF_COMPARE(sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getData(), tcpLayer.getData(), sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getDataLen());
	PTF_ASSERT_EQUAL(tcpLayer.getTcpOptionCount(), sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getTcpOptionCount(), size);
	PTF_ASSERT_TRUE(sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP).getRecordBasePtr() != tcpLayer.getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP).getRecordBasePtr());
	PTF_ASSERT_TRUE(sampleTcpPacketWithOptions.getLayerOfType<pcpp::TcpLayer>()->getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP) == tcpLayer.getTcpOption(pcpp::PCPP_TCPOPT_TIMESTAMP));


	//HttpLayer copy c'tor test
	//--------------------------

	pcpp::HttpResponseLayer* sampleHttpLayer = sampleHttpPacket.getLayerOfType<pcpp::HttpResponseLayer>();
	pcpp::HttpResponseLayer httpResLayer = *sampleHttpPacket.getLayerOfType<pcpp::HttpResponseLayer>();
	PTF_ASSERT_TRUE(sampleHttpLayer->getFirstLine() != httpResLayer.getFirstLine());
	PTF_ASSERT_EQUAL(sampleHttpLayer->getFirstLine()->getStatusCode(), httpResLayer.getFirstLine()->getStatusCode(), enum);
	PTF_ASSERT_EQUAL(sampleHttpLayer->getFirstLine()->getSize(), httpResLayer.getFirstLine()->getSize(), int);
	PTF_ASSERT_EQUAL(sampleHttpLayer->getFirstLine()->getVersion(), httpResLayer.getFirstLine()->getVersion(), enum);

	pcpp::HeaderField* curFieldInSample = sampleHttpLayer->getFirstField();
	pcpp::HeaderField* curFieldInCopy = httpResLayer.getFirstField();
	while (curFieldInSample != NULL && curFieldInCopy != NULL)
	{
		PTF_ASSERT_TRUE(curFieldInCopy != curFieldInSample);
		PTF_ASSERT_EQUAL(curFieldInSample->getFieldName(), curFieldInCopy->getFieldName(), string);
		PTF_ASSERT_EQUAL(curFieldInSample->getFieldValue(), curFieldInCopy->getFieldValue(), string);
		PTF_ASSERT_EQUAL(curFieldInSample->getFieldSize(), curFieldInCopy->getFieldSize(), size);

		curFieldInSample = sampleHttpLayer->getNextField(curFieldInSample);
		curFieldInCopy = sampleHttpLayer->getNextField(curFieldInCopy);
	}

	PTF_ASSERT_NULL(curFieldInSample);
	PTF_ASSERT_NULL(curFieldInCopy);


	//Packet copy c'tor test - Ethernet
	//---------------------------------

	pcpp::Packet samplePacketCopy(sampleHttpPacket);
	PTF_ASSERT_TRUE(samplePacketCopy.getFirstLayer() != sampleHttpPacket.getFirstLayer());
	PTF_ASSERT_TRUE(samplePacketCopy.getLastLayer() != sampleHttpPacket.getLastLayer());
	PTF_ASSERT_TRUE(samplePacketCopy.getRawPacket() != sampleHttpPacket.getRawPacket());
	PTF_ASSERT_EQUAL(samplePacketCopy.getRawPacket()->getRawDataLen(), sampleHttpPacket.getRawPacket()->getRawDataLen(), int);
	PTF_ASSERT_BUF_COMPARE(samplePacketCopy.getRawPacket()->getRawData(), sampleHttpPacket.getRawPacket()->getRawData(), sampleHttpPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_TRUE(samplePacketCopy.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_TRUE(samplePacketCopy.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_TRUE(samplePacketCopy.isPacketOfType(pcpp::TCP));
	PTF_ASSERT_TRUE(samplePacketCopy.isPacketOfType(pcpp::HTTPResponse));
	pcpp::Layer* curSamplePacketLayer = sampleHttpPacket.getFirstLayer();
	pcpp::Layer* curPacketCopyLayer = samplePacketCopy.getFirstLayer();
	while (curSamplePacketLayer != NULL && curPacketCopyLayer != NULL)
	{
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getProtocol(), curPacketCopyLayer->getProtocol(), u64);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getHeaderLen(), curPacketCopyLayer->getHeaderLen(), size);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getLayerPayloadSize(), curPacketCopyLayer->getLayerPayloadSize(), size);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getDataLen(), curPacketCopyLayer->getDataLen(), size);
		PTF_ASSERT_BUF_COMPARE(curSamplePacketLayer->getData(), curPacketCopyLayer->getData(), curSamplePacketLayer->getDataLen());
		curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
		curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
	}

	PTF_ASSERT_NULL(curSamplePacketLayer);
	PTF_ASSERT_NULL(curPacketCopyLayer);


	//Packet copy c'tor test - Null/Loopback
	//--------------------------------------

	READ_FILE_AND_CREATE_PACKET_LINKTYPE(3, "PacketExamples/NullLoopback1.dat", pcpp::LINKTYPE_NULL);

	pcpp::Packet nullLoopbackPacket(&rawPacket3);

	pcpp::Packet nullLoopbackPacketCopy(nullLoopbackPacket);

	PTF_ASSERT_TRUE(nullLoopbackPacketCopy.getFirstLayer() != nullLoopbackPacket.getFirstLayer());
	PTF_ASSERT_TRUE(nullLoopbackPacketCopy.getLastLayer() != nullLoopbackPacket.getLastLayer());
	PTF_ASSERT_TRUE(nullLoopbackPacketCopy.getRawPacket() != nullLoopbackPacket.getRawPacket());
	PTF_ASSERT_EQUAL(nullLoopbackPacketCopy.getRawPacket()->getRawDataLen(), nullLoopbackPacket.getRawPacket()->getRawDataLen(), int);
	PTF_ASSERT_BUF_COMPARE(nullLoopbackPacketCopy.getRawPacket()->getRawData(), nullLoopbackPacket.getRawPacket()->getRawData(), nullLoopbackPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_EQUAL(nullLoopbackPacketCopy.getRawPacket()->getLinkLayerType(), pcpp::LINKTYPE_NULL, enum);
	PTF_ASSERT_EQUAL(nullLoopbackPacketCopy.getFirstLayer()->getProtocol(), pcpp::NULL_LOOPBACK, u64);

	curSamplePacketLayer = nullLoopbackPacket.getFirstLayer();
	curPacketCopyLayer = nullLoopbackPacketCopy.getFirstLayer();
	while (curSamplePacketLayer != NULL && curPacketCopyLayer != NULL)
	{
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getProtocol(), curPacketCopyLayer->getProtocol(), u64);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getHeaderLen(), curPacketCopyLayer->getHeaderLen(), size);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getLayerPayloadSize(), curPacketCopyLayer->getLayerPayloadSize(), size);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getDataLen(), curPacketCopyLayer->getDataLen(), size);
		curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
		curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
	}


	//Packet copy c'tor test - SLL
	//----------------------------

	READ_FILE_AND_CREATE_PACKET_LINKTYPE(4, "PacketExamples/SllPacket2.dat", pcpp::LINKTYPE_LINUX_SLL);

	pcpp::Packet sllPacket(&rawPacket4);

	pcpp::Packet sllPacketCopy(sllPacket);

	PTF_ASSERT_TRUE(sllPacketCopy.getFirstLayer() != sllPacket.getFirstLayer());
	PTF_ASSERT_TRUE(sllPacketCopy.getLastLayer() != sllPacket.getLastLayer());
	PTF_ASSERT_TRUE(sllPacketCopy.getRawPacket() != sllPacket.getRawPacket());
	PTF_ASSERT_EQUAL(sllPacketCopy.getRawPacket()->getRawDataLen(), sllPacket.getRawPacket()->getRawDataLen(), int);
	PTF_ASSERT_BUF_COMPARE(sllPacketCopy.getRawPacket()->getRawData(), sllPacket.getRawPacket()->getRawData(), sllPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_EQUAL(sllPacketCopy.getRawPacket()->getLinkLayerType(), pcpp::LINKTYPE_LINUX_SLL, enum);
	PTF_ASSERT_EQUAL(sllPacketCopy.getFirstLayer()->getProtocol(), pcpp::SLL, u64);

	curSamplePacketLayer = sllPacket.getFirstLayer();
	curPacketCopyLayer = sllPacketCopy.getFirstLayer();
	while (curSamplePacketLayer != NULL && curPacketCopyLayer != NULL)
	{
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getProtocol(), curPacketCopyLayer->getProtocol(), u64);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getHeaderLen(), curPacketCopyLayer->getHeaderLen(), size);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getLayerPayloadSize(), curPacketCopyLayer->getLayerPayloadSize(), size);
		PTF_ASSERT_EQUAL(curSamplePacketLayer->getDataLen(), curPacketCopyLayer->getDataLen(), size);
		curSamplePacketLayer = curSamplePacketLayer->getNextLayer();
		curPacketCopyLayer = curPacketCopyLayer->getNextLayer();
	}


	//DnsLayer copy c'tor and operator= test
	//--------------------------------------

	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/Dns2.dat");

	pcpp::Packet sampleDnsPacket(&rawPacket5);

	pcpp::DnsLayer* origDnsLayer = sampleDnsPacket.getLayerOfType<pcpp::DnsLayer>();
	PTF_ASSERT_NOT_NULL(origDnsLayer);
	pcpp::DnsLayer copyDnsLayer(*origDnsLayer);
	PTF_ASSERT_EQUAL(copyDnsLayer.getQueryCount(), origDnsLayer->getQueryCount(), size);
	PTF_ASSERT_EQUAL(copyDnsLayer.getFirstQuery()->getName(), origDnsLayer->getFirstQuery()->getName(), string);
	PTF_ASSERT_EQUAL(copyDnsLayer.getFirstQuery()->getDnsType(), origDnsLayer->getFirstQuery()->getDnsType(), enum);

	PTF_ASSERT_EQUAL(copyDnsLayer.getAuthorityCount(), origDnsLayer->getAuthorityCount(), size);
	PTF_ASSERT_EQUAL(copyDnsLayer.getAuthority("Yaels-iPhone.local", true)->getData()->toString(), origDnsLayer->getAuthority("Yaels-iPhone.local", true)->getData()->toString(), string);

	PTF_ASSERT_EQUAL(copyDnsLayer.getAdditionalRecord("", true)->getData()->toString(), origDnsLayer->getAdditionalRecord("", true)->getData()->toString(), string);

	copyDnsLayer.addQuery("bla", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_ANY);
	pcpp::IPv4DnsResourceData ipv4DnsData(std::string("1.1.1.1"));
	copyDnsLayer.addAnswer("bla", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_ANY, 123, &ipv4DnsData);

	copyDnsLayer = *origDnsLayer;

	PTF_ASSERT_EQUAL(copyDnsLayer.getQueryCount(), origDnsLayer->getQueryCount(), size);
	PTF_ASSERT_EQUAL(copyDnsLayer.getFirstQuery()->getName(), origDnsLayer->getFirstQuery()->getName(), string);
	PTF_ASSERT_EQUAL(copyDnsLayer.getFirstQuery()->getDnsType(), origDnsLayer->getFirstQuery()->getDnsType(), enum);

	PTF_ASSERT_EQUAL(copyDnsLayer.getAuthorityCount(), origDnsLayer->getAuthorityCount(), size);
	PTF_ASSERT_EQUAL(copyDnsLayer.getAuthority(".local", false)->getData()->toString(), origDnsLayer->getAuthority("iPhone.local", false)->getData()->toString(), string);

	PTF_ASSERT_EQUAL(copyDnsLayer.getAnswerCount(), origDnsLayer->getAnswerCount(), size);

	PTF_ASSERT_EQUAL(copyDnsLayer.getAdditionalRecord("", true)->getData()->toString(), origDnsLayer->getAdditionalRecord("", true)->getData()->toString(), string);

} // CopyLayerAndPacketTest


PTF_TEST_CASE(PacketLayerLookupTest)
{
	timeval time;
	gettimeofday(&time, NULL);

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
		PTF_ASSERT_EQUAL(ipLayer->getSrcIpAddress(), pcpp::IPv4Address("192.168.203.3"), object);
		PTF_ASSERT_EQUAL(ipLayer->getDstIpAddress(), pcpp::IPv4Address("192.168.203.5"), object);

		// get the first IPv4 layer
		ipLayer = vxlanPacket.getPrevLayerOfType<pcpp::IPv4Layer>(ipLayer);
		PTF_ASSERT_NOT_NULL(ipLayer);
		PTF_ASSERT_EQUAL(ipLayer->getSrcIpAddress(), pcpp::IPv4Address("192.168.203.1"), object);
		PTF_ASSERT_EQUAL(ipLayer->getDstIpAddress(), pcpp::IPv4Address("192.168.202.1"), object);

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
} // PacketLayerLookupTest


PTF_TEST_CASE(RawPacketTimeStampSetterTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv6UdpPacket.dat");

	timeval usec_test_time;
	timespec nsec_test_time;
	timespec expected_ts;

	//test usec-precision setter
	usec_test_time.tv_sec = 1583840642; //10.03.2020 15:44
	usec_test_time.tv_usec = 111222;
	expected_ts.tv_sec = usec_test_time.tv_sec;
	expected_ts.tv_nsec = usec_test_time.tv_usec * 1000;

	PTF_ASSERT_TRUE(rawPacket1.setPacketTimeStamp(usec_test_time));
	PTF_ASSERT_EQUAL(rawPacket1.getPacketTimeStamp().tv_sec, expected_ts.tv_sec, u32);
	PTF_ASSERT_EQUAL(rawPacket1.getPacketTimeStamp().tv_nsec, expected_ts.tv_nsec, u32);

	//test nsec-precision setter
	nsec_test_time.tv_sec = 1583842105; //10.03.2020 16:08
	nsec_test_time.tv_nsec = 111222987;
	expected_ts = nsec_test_time;

	PTF_ASSERT_TRUE(rawPacket1.setPacketTimeStamp(nsec_test_time));
	PTF_ASSERT_EQUAL(rawPacket1.getPacketTimeStamp().tv_sec, expected_ts.tv_sec, u32);
	PTF_ASSERT_EQUAL(rawPacket1.getPacketTimeStamp().tv_nsec, expected_ts.tv_nsec, u32);
} // RawPacketTimeStampSetterTest



PTF_TEST_CASE(ParsePartialPacketTest)
{
	timeval time;
	gettimeofday(&time, NULL);

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
} // ParsePartialPacketTest