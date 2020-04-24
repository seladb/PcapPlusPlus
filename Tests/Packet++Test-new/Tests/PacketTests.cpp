#include "../Utils/TestUtils.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "VlanLayer.h"
#include "IcmpLayer.h"
#include "TcpLayer.h"
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