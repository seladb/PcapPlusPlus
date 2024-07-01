#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "EthLayer.h"
#include "GeneralUtils.h"
#include "IPv6Layer.h"
#include "IcmpV6Layer.h"
#include "Logger.h"
#include "MacAddress.h"
#include "NdpLayer.h"
#include "Packet.h"
#include "SystemUtils.h"
#include "VlanLayer.h"
#include <sstream>

PTF_TEST_CASE(IcmpV6ParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_EchoRequest.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IcmpV6_EchoReply.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/IcmpV6_NeighSoli.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/IcmpV6_NeighAdv.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/IcmpV6_NeighAdvNoOption.dat");
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/IcmpV6_Generic.dat");

	pcpp::Packet echoRequestPacket(&rawPacket1);
	pcpp::Packet echoReplyPacket(&rawPacket2);
	pcpp::Packet neighSoliPacket(&rawPacket3);
	pcpp::Packet neighAdvPacket(&rawPacket4);
	pcpp::Packet neighAdvPacketNoOpt(&rawPacket5);
	pcpp::Packet icmpV6GenericPacket(&rawPacket6);

	// Echo request
	PTF_ASSERT_TRUE(echoRequestPacket.isPacketOfType(pcpp::ICMPv6));
	pcpp::ICMPv6EchoLayer* echoRequestLayer = echoRequestPacket.getLayerOfType<pcpp::ICMPv6EchoLayer>();
	PTF_ASSERT_NOT_NULL(echoRequestLayer);
	PTF_ASSERT_TRUE(echoRequestLayer->isMessageOfType(pcpp::ICMPv6MessageType::ICMPv6_ECHO_REQUEST));
	PTF_ASSERT_EQUAL(echoRequestLayer->getMessageType(), pcpp::ICMPv6MessageType::ICMPv6_ECHO_REQUEST, enumclass);
	PTF_ASSERT_EQUAL(echoRequestLayer->getCode(), 0);
	PTF_ASSERT_EQUAL(echoRequestLayer->getChecksum(), 0x7a4c);
	PTF_ASSERT_EQUAL(echoRequestLayer->getIdentifier(), 0x0018);
	PTF_ASSERT_EQUAL(echoRequestLayer->getSequenceNr(), 20);
	PTF_ASSERT_EQUAL(echoRequestLayer->getEchoDataLen(), 56);

	uint8_t data[] = { 0xbd, 0xce, 0xcb, 0x62 };
	PTF_ASSERT_BUF_COMPARE(echoRequestLayer->getEchoDataPtr(), data, 4);

	// Echo reply
	PTF_ASSERT_TRUE(echoReplyPacket.isPacketOfType(pcpp::ICMPv6));
	pcpp::ICMPv6EchoLayer* echoReplyLayer = echoReplyPacket.getLayerOfType<pcpp::ICMPv6EchoLayer>();
	PTF_ASSERT_NOT_NULL(echoReplyLayer);
	PTF_ASSERT_TRUE(echoReplyLayer->isMessageOfType(pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY));
	PTF_ASSERT_EQUAL(echoReplyLayer->getMessageType(), pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY, enumclass);
	PTF_ASSERT_EQUAL(echoReplyLayer->getCode(), 0);
	PTF_ASSERT_EQUAL(echoReplyLayer->getChecksum(), 0x794c);
	PTF_ASSERT_EQUAL(echoReplyLayer->getIdentifier(), 0x0018);
	PTF_ASSERT_EQUAL(echoReplyLayer->getSequenceNr(), 20);
	PTF_ASSERT_EQUAL(echoReplyLayer->getEchoDataLen(), 56);

	PTF_ASSERT_BUF_COMPARE(echoReplyLayer->getEchoDataPtr(), data, 4);

	// Neighbor solicitation with source link-layer option
	PTF_ASSERT_TRUE(neighSoliPacket.isPacketOfType(pcpp::ICMPv6));
	pcpp::NDPNeighborSolicitationLayer* neighSoliLayer =
	    neighSoliPacket.getLayerOfType<pcpp::NDPNeighborSolicitationLayer>();
	PTF_ASSERT_NOT_NULL(neighSoliLayer);
	PTF_ASSERT_EQUAL(neighSoliLayer->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(neighSoliLayer->getMessageType(), pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION,
	                 enumclass);
	PTF_ASSERT_EQUAL(neighSoliLayer->getCode(), 0);
	PTF_ASSERT_EQUAL(neighSoliLayer->getChecksum(), 0xfe98);
	PTF_ASSERT_EQUAL(neighSoliLayer->getTargetIP(), pcpp::IPv6Address("fd53:7cb8:383:2::1:117"));
	PTF_ASSERT_TRUE(neighSoliLayer->hasLinkLayerAddress());
	PTF_ASSERT_EQUAL(neighSoliLayer->getLinkLayerAddress(), pcpp::MacAddress("00:54:af:e9:4d:80"));
	PTF_ASSERT_EQUAL(neighSoliLayer->getNdpOptionCount(), 1);

	pcpp::NdpOption sourceLinkLayerOption =
	    neighSoliLayer->getNdpOption(pcpp::NDPNeighborOptionTypes::NDP_OPTION_SOURCE_LINK_LAYER);
	PTF_ASSERT_TRUE(sourceLinkLayerOption.isNotNull());
	PTF_ASSERT_EQUAL((int)sourceLinkLayerOption.getNdpOptionType(), 1);
	PTF_ASSERT_EQUAL(sourceLinkLayerOption.getDataSize(), 6);
	PTF_ASSERT_EQUAL(sourceLinkLayerOption.getTotalSize(), 8);
	PTF_ASSERT_EQUAL(pcpp::MacAddress(sourceLinkLayerOption.getValue()), pcpp::MacAddress("00:54:af:e9:4d:80"));
	pcpp::NdpOption targetLinkLayerOption2 =
	    neighSoliLayer->getNdpOption(pcpp::NDPNeighborOptionTypes::NDP_OPTION_TARGET_LINK_LAYER);
	PTF_ASSERT_TRUE(targetLinkLayerOption2.isNull());

	pcpp::IcmpV6Layer* icmpNeighSoliLayer = neighSoliPacket.getLayerOfType<pcpp::IcmpV6Layer>();
	PTF_ASSERT_EQUAL(icmpNeighSoliLayer->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(icmpNeighSoliLayer->getMessageType(), pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION,
	                 enumclass);
	PTF_ASSERT_EQUAL(icmpNeighSoliLayer->getCode(), 0);
	PTF_ASSERT_EQUAL(icmpNeighSoliLayer->getChecksum(), 0xfe98);

	// Neighbor advertisement with target link-layer option
	PTF_ASSERT_TRUE(neighAdvPacket.isPacketOfType(pcpp::ICMPv6));
	pcpp::NDPNeighborAdvertisementLayer* neighAdvLayer =
	    neighAdvPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();
	PTF_ASSERT_EQUAL(neighAdvLayer->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(neighAdvLayer->getMessageType(), pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT,
	                 enumclass);
	PTF_ASSERT_EQUAL(neighAdvLayer->getCode(), 0);
	PTF_ASSERT_EQUAL(neighAdvLayer->getChecksum(), 0x9abb);
	PTF_ASSERT_TRUE(neighAdvLayer->getRouterFlag());
	PTF_ASSERT_FALSE(neighAdvLayer->getUnicastFlag());
	PTF_ASSERT_TRUE(neighAdvLayer->getOverrideFlag());
	PTF_ASSERT_EQUAL(neighAdvLayer->getTargetIP(), pcpp::IPv6Address("fe80::c000:54ff:fef5:0"));
	PTF_ASSERT_TRUE(neighAdvLayer->hasTargetMacInfo());
	PTF_ASSERT_EQUAL(neighAdvLayer->getTargetMac(), pcpp::MacAddress("c2:00:54:f5:00:00"));
	PTF_ASSERT_EQUAL(neighAdvLayer->getNdpOptionCount(), 1);

	pcpp::NdpOption targetLinkLayerOption =
	    neighAdvLayer->getNdpOption(pcpp::NDPNeighborOptionTypes::NDP_OPTION_TARGET_LINK_LAYER);
	PTF_ASSERT_TRUE(targetLinkLayerOption.isNotNull());
	PTF_ASSERT_EQUAL((int)targetLinkLayerOption.getNdpOptionType(), 2);
	PTF_ASSERT_EQUAL(targetLinkLayerOption.getDataSize(), 6);
	PTF_ASSERT_EQUAL(targetLinkLayerOption.getTotalSize(), 8);
	PTF_ASSERT_EQUAL(pcpp::MacAddress(targetLinkLayerOption.getValue()), pcpp::MacAddress("c2:00:54:f5:00:00"));

	pcpp::IcmpV6Layer* icmpNeighAdv = neighAdvPacket.getLayerOfType<pcpp::IcmpV6Layer>();
	PTF_ASSERT_EQUAL(icmpNeighAdv->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(icmpNeighAdv->getMessageType(), pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT, enumclass);
	PTF_ASSERT_EQUAL(icmpNeighAdv->getCode(), 0);
	PTF_ASSERT_EQUAL(icmpNeighAdv->getChecksum(), 0x9abb);

	// Neighbor advertisement without target link-layer option
	PTF_ASSERT_TRUE(neighAdvPacketNoOpt.isPacketOfType(pcpp::ICMPv6));
	pcpp::NDPNeighborAdvertisementLayer* neighAdvNoOptLayer =
	    neighAdvPacketNoOpt.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();
	PTF_ASSERT_EQUAL(neighAdvNoOptLayer->getHeaderLen(), 24);
	PTF_ASSERT_FALSE(neighAdvNoOptLayer->getRouterFlag());
	PTF_ASSERT_TRUE(neighAdvNoOptLayer->getUnicastFlag());
	PTF_ASSERT_FALSE(neighAdvNoOptLayer->getOverrideFlag());
	PTF_ASSERT_EQUAL(neighAdvNoOptLayer->getTargetIP(), pcpp::IPv6Address("fe80:ebeb:ebeb::1"));
	PTF_ASSERT_FALSE(neighAdvNoOptLayer->hasTargetMacInfo());
	PTF_ASSERT_EQUAL(neighAdvNoOptLayer->getTargetMac(), pcpp::MacAddress());
	PTF_ASSERT_EQUAL(neighAdvNoOptLayer->getNdpOptionCount(), 0);
	pcpp::NdpOption targetLinkLayerNoOptOption =
	    neighAdvNoOptLayer->getNdpOption(pcpp::NDPNeighborOptionTypes::NDP_OPTION_TARGET_LINK_LAYER);
	PTF_ASSERT_TRUE(targetLinkLayerNoOptOption.isNull());

	// Generic ICMPv6 packet
	PTF_ASSERT_TRUE(icmpV6GenericPacket.isPacketOfType(pcpp::ICMPv6));
	pcpp::IcmpV6Layer* icmpV6Layer = icmpV6GenericPacket.getLayerOfType<pcpp::IcmpV6Layer>();
	PTF_ASSERT_NOT_NULL(icmpV6Layer);
	PTF_ASSERT_EQUAL(icmpV6Layer->getHeaderLen(), 48);
	PTF_ASSERT_TRUE(icmpV6Layer->isMessageOfType(pcpp::ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_DISCOVERY_REPORTS));
	PTF_ASSERT_EQUAL(icmpV6Layer->getMessageType(),
	                 pcpp::ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_DISCOVERY_REPORTS, enumclass);
	PTF_ASSERT_EQUAL(icmpV6Layer->getCode(), 0);
	PTF_ASSERT_EQUAL(icmpV6Layer->getChecksum(), 0x2b5a);
	PTF_ASSERT_EQUAL(icmpV6Layer->toString(), "ICMPv6 Layer, Message type: 143");
	PTF_ASSERT_NULL(icmpV6Layer->getNextLayer());
	std::string expectedPayloadString =
	    "0000000204000000ff05000000000000000000000001000304000000ff020000000000000000000000010002";
	PTF_ASSERT_EQUAL(pcpp::byteArrayToHexString(icmpV6Layer->getDataPtr(4), icmpV6Layer->getDataLen() - 4),
	                 expectedPayloadString);
}

PTF_TEST_CASE(IcmpV6CreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/IcmpV6_EchoRequest.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/IcmpV6_EchoReply.dat");
	READ_FILE_INTO_BUFFER(3, "PacketExamples/IcmpV6_NeighSoli.dat");
	READ_FILE_INTO_BUFFER(4, "PacketExamples/IcmpV6_NeighAdv.dat");
	READ_FILE_INTO_BUFFER(5, "PacketExamples/IcmpV6_NeighAdvNoOption.dat");
	READ_FILE_INTO_BUFFER(6, "PacketExamples/IcmpV6_Generic.dat");

	uint8_t data[56] = { 0xbd, 0xce, 0xcb, 0x62, 0x00, 0x00, 0x00, 0x00, 0xf3, 0xa1, 0x09, 0x00, 0x00, 0x00,
		                 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
		                 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		                 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 };

	pcpp::EthLayer ethLayer(pcpp::MacAddress("11:22:33:44:55:66"), pcpp::MacAddress("66:55:44:33:22:11"));
	pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address(std::string("fe80::215:5dff:fea5:c4c5")),
	                          pcpp::IPv6Address(std::string("fe80::dd05:dae0:74bc:7341")));

	// Create ICMPv6 layer with type, code and data
	pcpp::IcmpV6Layer icmpv6Layer(pcpp::ICMPv6MessageType::ICMPv6_ECHO_REQUEST, 0, data, 56);
	pcpp::Packet icmpv6LayerPacket(100);
	PTF_ASSERT_TRUE(icmpv6LayerPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(icmpv6LayerPacket.addLayer(&ipv6Layer));
	PTF_ASSERT_TRUE(icmpv6LayerPacket.addLayer(&icmpv6Layer));
	icmpv6LayerPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(
	    icmpv6LayerPacket.getRawPacket()->getRawDataLen(),
	    bufferLength1 -
	        4);  // comparing with IcmpV6_EchoRequest frame which has the same data but an additional echo header
	PTF_ASSERT_BUF_COMPARE(icmpv6LayerPacket.getRawPacket()->getRawData() + 58, buffer1 + 62, bufferLength1 - 62);

	// Echo request creation
	pcpp::EthLayer ethLayer1(ethLayer);
	pcpp::IPv6Layer ipv6Layer1(ipv6Layer);
	pcpp::ICMPv6EchoLayer echoReqLayer(pcpp::ICMPv6EchoLayer::REQUEST, 0x0018, 20, data, 56);
	pcpp::Packet echoRequestPacket(100);
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&ethLayer1));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&ipv6Layer1));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&echoReqLayer));
	echoRequestPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(echoRequestPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(echoRequestPacket.getRawPacket()->getRawData() + 54, buffer1 + 54, bufferLength1 - 54);

	// Echo reply creation
	pcpp::EthLayer ethLayer2(ethLayer);
	pcpp::IPv6Layer ipLayer2(ipv6Layer);
	pcpp::ICMPv6EchoLayer echoRepLayer(pcpp::ICMPv6EchoLayer::REPLY, 0x0018, 20, data, 56);
	pcpp::Packet echoReplyPacket(100);
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&ipLayer2));
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&echoRepLayer));
	echoReplyPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(echoReplyPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(echoReplyPacket.getRawPacket()->getRawData() + 54, buffer2 + 54, bufferLength2 - 54);

	// Neighbor solicitation with source link-layer option
	pcpp::IPv6Layer* ipv6SoliLayer =
	    new pcpp::IPv6Layer(pcpp::IPv6Address("fd53:7cb8:383:4::67"), pcpp::IPv6Address("fd53:7cb8:383:2::1:117"));
	ipv6SoliLayer->getIPv6Header()->hopLimit = 255;
	pcpp::NDPNeighborSolicitationLayer* ndpSoliLayer = new pcpp::NDPNeighborSolicitationLayer(
	    0, pcpp::IPv6Address("fd53:7cb8:383:2::1:117"), pcpp::MacAddress("00:54:af:e9:4d:80"));
	pcpp::Packet neighSoliPacket(100);
	PTF_ASSERT_TRUE(neighSoliPacket.addLayer(ipv6SoliLayer, true));
	PTF_ASSERT_TRUE(neighSoliPacket.addLayer(ndpSoliLayer, true));
	neighSoliPacket.computeCalculateFields();
	PTF_ASSERT_BUF_COMPARE(
	    neighSoliPacket.getRawPacket()->getRawData() + 6, buffer3 + 24,
	    bufferLength3 -
	        28);  // dat file contains frame with eth + vlan layer (14 + 4 bytes) and  trailing bytes (4 bytes)

	pcpp::NDPNeighborSolicitationLayer* neighSoliLayer =
	    neighSoliPacket.getLayerOfType<pcpp::NDPNeighborSolicitationLayer>();
	PTF_ASSERT_EQUAL(neighSoliLayer->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL((int)neighSoliLayer->getMessageType(), 135);
	PTF_ASSERT_EQUAL(neighSoliLayer->getCode(), 0);
	PTF_ASSERT_EQUAL(neighSoliLayer->getChecksum(), 0xfe98);
	PTF_ASSERT_EQUAL(neighSoliLayer->getTargetIP(), pcpp::IPv6Address("fd53:7cb8:383:2::1:117"));
	PTF_ASSERT_EQUAL(neighSoliLayer->getNdpOptionCount(), 1);
	PTF_ASSERT_EQUAL(neighSoliLayer->getLinkLayerAddress(), pcpp::MacAddress("00:54:af:e9:4d:80"));
	pcpp::NdpOption sourceLinkLayerOption =
	    neighSoliLayer->getNdpOption(pcpp::NDPNeighborOptionTypes::NDP_OPTION_SOURCE_LINK_LAYER);
	PTF_ASSERT_TRUE(sourceLinkLayerOption.isNotNull());
	PTF_ASSERT_EQUAL(sourceLinkLayerOption.getDataSize(), 6);
	PTF_ASSERT_EQUAL(sourceLinkLayerOption.getTotalSize(), 8);

	// Neighbor advertisement with target link-layer option
	pcpp::IPv6Layer* ipv6AdvLayer =
	    new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::IPv6Address("ff02::1"));
	pcpp::NDPNeighborAdvertisementLayer* ndpAdvLayer = new pcpp::NDPNeighborAdvertisementLayer(
	    0, pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::MacAddress("c2:00:54:f5:00:00"), true, false, true);
	pcpp::Packet neighAdvPacket(100);
	PTF_ASSERT_TRUE(neighAdvPacket.addLayer(ipv6AdvLayer, true));
	PTF_ASSERT_TRUE(neighAdvPacket.addLayer(ndpAdvLayer, true));
	neighAdvPacket.computeCalculateFields();
	PTF_ASSERT_BUF_COMPARE(neighAdvPacket.getRawPacket()->getRawData() + 40, buffer4 + 54, bufferLength4 - 54);

	pcpp::NDPNeighborAdvertisementLayer* neighAdvLayer =
	    neighAdvPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();
	PTF_ASSERT_EQUAL(neighAdvLayer->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL((int)neighAdvLayer->getMessageType(), 136);
	PTF_ASSERT_EQUAL(neighAdvLayer->getCode(), 0);
	PTF_ASSERT_EQUAL(neighAdvLayer->getChecksum(), 0x9abb);
	PTF_ASSERT_TRUE(neighAdvLayer->getRouterFlag());
	PTF_ASSERT_FALSE(neighAdvLayer->getUnicastFlag());
	PTF_ASSERT_TRUE(neighAdvLayer->getOverrideFlag());
	PTF_ASSERT_EQUAL(neighAdvLayer->getTargetIP(), pcpp::IPv6Address("fe80::c000:54ff:fef5:0"));
	PTF_ASSERT_EQUAL(neighAdvLayer->getNdpOptionCount(), 1);
	PTF_ASSERT_EQUAL(neighAdvLayer->getTargetMac(), pcpp::MacAddress("c2:00:54:f5:00:00"));
	pcpp::NdpOption targetLinkLayerOption =
	    neighAdvLayer->getNdpOption(pcpp::NDPNeighborOptionTypes::NDP_OPTION_TARGET_LINK_LAYER);
	PTF_ASSERT_TRUE(targetLinkLayerOption.isNotNull());
	PTF_ASSERT_EQUAL(targetLinkLayerOption.getDataSize(), 6);
	PTF_ASSERT_EQUAL(targetLinkLayerOption.getTotalSize(), 8);

	// Neighbor advertisement without option
	pcpp::IPv6Layer* ipv6AdvLayer2 =
	    new pcpp::IPv6Layer(pcpp::IPv6Address("fe80:ebeb:ebeb::1"), pcpp::IPv6Address("fe80:ebeb:ebeb::2"));
	pcpp::NDPNeighborAdvertisementLayer* ndpAdvLayer2 =
	    new pcpp::NDPNeighborAdvertisementLayer(0, pcpp::IPv6Address("fe80:ebeb:ebeb::1"), false, true, false);
	pcpp::Packet neighAdvPacket2(100);
	PTF_ASSERT_TRUE(neighAdvPacket2.addLayer(ipv6AdvLayer2, true));
	PTF_ASSERT_TRUE(neighAdvPacket2.addLayer(ndpAdvLayer2, true));
	neighAdvPacket2.computeCalculateFields();
	PTF_ASSERT_BUF_COMPARE(neighAdvPacket2.getRawPacket()->getRawData() + 40, buffer5 + 54,
	                       bufferLength5 - 58);  // dat file contains eth layer (14 bytes) and trailing bytes (4 bytes)

	pcpp::NDPNeighborAdvertisementLayer* neighAdvLayer2 =
	    neighAdvPacket2.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();
	PTF_ASSERT_EQUAL(neighAdvLayer2->getHeaderLen(), 24);
	PTF_ASSERT_EQUAL((int)neighAdvLayer2->getMessageType(), 136);
	PTF_ASSERT_EQUAL(neighAdvLayer2->getCode(), 0);
	PTF_ASSERT_EQUAL(neighAdvLayer2->getChecksum(), 0xb49e);
	PTF_ASSERT_FALSE(neighAdvLayer2->getRouterFlag());
	PTF_ASSERT_TRUE(neighAdvLayer2->getUnicastFlag());
	PTF_ASSERT_FALSE(neighAdvLayer2->getOverrideFlag());
	PTF_ASSERT_EQUAL(neighAdvLayer2->getTargetIP(), pcpp::IPv6Address("fe80:ebeb:ebeb::1"));
	PTF_ASSERT_EQUAL(neighAdvLayer2->getNdpOptionCount(), 0);
	PTF_ASSERT_FALSE(neighAdvLayer2->hasTargetMacInfo());
	PTF_ASSERT_EQUAL(neighAdvLayer2->getTargetMac(), pcpp::MacAddress());

	// Generic ICMPv6 packet
	pcpp::IPv6Layer* ipv6Layer2 =
	    new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::a00:27ff:fed4:10bb"), pcpp::IPv6Address("ff02::16"));
	ipv6Layer2->getIPv6Header()->hopLimit = 1;

	std::vector<pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder> hopByHopExtOptions;
	hopByHopExtOptions.push_back(pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(5, (uint16_t)0));
	hopByHopExtOptions.push_back(pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(1, nullptr, 0));
	pcpp::IPv6HopByHopHeader newHopByHopHeader(hopByHopExtOptions);
	ipv6Layer2->addExtension<pcpp::IPv6HopByHopHeader>(newHopByHopHeader);
	ipv6Layer2->getDataPtr(40)[0] = 0x3a;

	uint8_t data2[44] = { 0x00, 0x00, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
		                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x04, 0x00, 0x00, 0x00, 0xff, 0x02,
		                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02 };

	pcpp::IcmpV6Layer* icmpV6GenericLayer =
	    new pcpp::IcmpV6Layer(pcpp::ICMPv6MessageType::ICMPv6_MULTICAST_LISTENER_DISCOVERY_REPORTS, 0, data2, 44);
	pcpp::Packet genericIcmpV6Packet(100);
	genericIcmpV6Packet.addLayer(ipv6Layer2, true);
	genericIcmpV6Packet.addLayer(icmpV6GenericLayer, true);
	genericIcmpV6Packet.computeCalculateFields();

	PTF_ASSERT_BUF_COMPARE(genericIcmpV6Packet.getRawPacket()->getRawData(), buffer6 + 14, bufferLength6 - 14);

	delete[] buffer1;
	delete[] buffer2;
	delete[] buffer3;
	delete[] buffer4;
	delete[] buffer5;
	delete[] buffer6;
}

PTF_TEST_CASE(IcmpV6EditTest)
{
	// Creates neighbor advertisement packet without option, adds two options and removes options afterwards.
	// Note: This is not a real packet, because neighbor advertisement packet can only contain one target link-layer
	// option but for testing NDP options and if padding bytes are handled correct (each option must be padded to 64-bit
	// boundary)
	pcpp::IPv6Layer* ipv6AdvLayer =
	    new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::IPv6Address("ff02::1"));
	pcpp::NDPNeighborAdvertisementLayer* ndpAdvLayer =
	    new pcpp::NDPNeighborAdvertisementLayer(0, pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), true, false, true);
	pcpp::Packet neighAdvPacket(100);
	PTF_ASSERT_TRUE(neighAdvPacket.addLayer(ipv6AdvLayer, true));
	PTF_ASSERT_TRUE(neighAdvPacket.addLayer(ndpAdvLayer, true));
	pcpp::NDPNeighborAdvertisementLayer* neighAdvLayer =
	    neighAdvPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

	uint8_t dataOption1[6] = { 0xc2, 0x00, 0x54, 0xf5, 0x01, 0x02 };
	neighAdvLayer->addNdpOption(pcpp::NdpOptionBuilder(pcpp::NDPNeighborOptionTypes::NDP_OPTION_TARGET_LINK_LAYER,
	                                                   dataOption1, 4));  // datalen is set to 4 -> for testing padding
	PTF_ASSERT_EQUAL(neighAdvLayer->getNdpOptionCount(), 1);
	PTF_ASSERT_EQUAL(neighAdvLayer->getHeaderLen(), 32);
	pcpp::NdpOption option1 = neighAdvLayer->getFirstNdpOption();
	PTF_ASSERT_TRUE(option1.isNotNull());
	PTF_ASSERT_EQUAL((int)option1.getNdpOptionType(), 2);
	PTF_ASSERT_EQUAL(option1.getDataSize(), 6);
	PTF_ASSERT_EQUAL(option1.getTotalSize(), 8);
	PTF_ASSERT_EQUAL(neighAdvLayer->getTargetMac(), pcpp::MacAddress("c2:00:54:f5:00:00"));
	neighAdvPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(neighAdvLayer->getChecksum(), 0x9abb);

	uint8_t dataOption2[6] = { 0xc2, 0x00, 0x54, 0xf5, 0x01, 0x02 };
	neighAdvLayer->addNdpOption(pcpp::NdpOptionBuilder(pcpp::NDPNeighborOptionTypes::NDP_OPTION_SOURCE_LINK_LAYER,
	                                                   dataOption2, 5));  // datalen is set to 5 -> for testing padding
	PTF_ASSERT_EQUAL(neighAdvLayer->getNdpOptionCount(), 2);
	PTF_ASSERT_EQUAL(neighAdvLayer->getHeaderLen(), 40);
	pcpp::NdpOption option2 = neighAdvLayer->getNextNdpOption(option1);
	PTF_ASSERT_TRUE(option2.isNotNull());
	PTF_ASSERT_EQUAL((int)option2.getNdpOptionType(), 1);
	PTF_ASSERT_EQUAL(option2.getDataSize(), 6);
	PTF_ASSERT_EQUAL(option2.getTotalSize(), 8);
	PTF_ASSERT_EQUAL(pcpp::MacAddress(option2.getValue()), pcpp::MacAddress("c2:00:54:f5:01:00"));

	PTF_ASSERT_TRUE(neighAdvLayer->removeAllNdpOptions());
	PTF_ASSERT_EQUAL(neighAdvLayer->getNdpOptionCount(), 0);
	PTF_ASSERT_EQUAL(neighAdvLayer->getHeaderLen(), 24);
}
