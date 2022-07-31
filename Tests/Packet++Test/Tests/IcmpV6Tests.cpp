#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "EthLayer.h"
#include "IPv6Layer.h"
#include "IcmpV6Layer.h"
#include "Logger.h"
#include "NdpLayer.h"
#include "Packet.h"
#include "SystemUtils.h"
#include <sstream>
#include <iomanip>

PTF_TEST_CASE(IcmpV6ParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_EchoRequest.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IcmpV6_EchoReply.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/IcmpV6_NeighSoli.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/IcmpV6_NeighAdv.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/IcmpV6_NeighAdvNoOption.dat");

	pcpp::Packet icmpv6EchoRequest(&rawPacket1);
	pcpp::Packet icmpv6EchoReply(&rawPacket2);
	pcpp::Packet icmpv6NeighSoli(&rawPacket3);
	pcpp::Packet icmpv6NeighAdv(&rawPacket4);
	pcpp::Packet icmpv6NeighAdvNoOpt(&rawPacket5);

	PTF_ASSERT_TRUE(icmpv6EchoRequest.isPacketOfType(pcpp::ICMPv6EchoRequest));
	PTF_ASSERT_TRUE(icmpv6EchoReply.isPacketOfType(pcpp::ICMPv6EchoReply));
	PTF_ASSERT_TRUE(icmpv6NeighSoli.isPacketOfType(pcpp::NDPNeighborSolicitation));
	PTF_ASSERT_TRUE(icmpv6NeighAdv.isPacketOfType(pcpp::NDPNeighborAdvertisement));

	// Echo request
	pcpp::ICMPv6EchoRequestLayer *icmpv6EchoRequestLayer = icmpv6EchoRequest.getLayerOfType<pcpp::ICMPv6EchoRequestLayer>();
	PTF_ASSERT_NOT_NULL(icmpv6EchoRequestLayer);
	PTF_ASSERT_TRUE(icmpv6EchoRequestLayer->isMessageOfType(pcpp::ICMPv6_ECHO_REQUEST));
	pcpp::icmpv6_echo_request *reqData = icmpv6EchoRequestLayer->getEchoRequestData();
	PTF_ASSERT_NOT_NULL(reqData);
	PTF_ASSERT_EQUAL(reqData->header->code, 0);
	PTF_ASSERT_EQUAL(reqData->header->checksum, 0x4c7a);
	PTF_ASSERT_EQUAL(reqData->header->id, 0x1800);
	PTF_ASSERT_EQUAL(reqData->header->sequence, 0x1400);
	PTF_ASSERT_EQUAL(reqData->dataLength, 56);
	PTF_ASSERT_EQUAL(reqData->data[3], 0x62);

	// Echo reply
	pcpp::ICMPv6EchoReplyLayer *icmpv6EchoReplyLayer = icmpv6EchoReply.getLayerOfType<pcpp::ICMPv6EchoReplyLayer>();
	PTF_ASSERT_NOT_NULL(icmpv6EchoReplyLayer);
	PTF_ASSERT_TRUE(icmpv6EchoReplyLayer->isMessageOfType(pcpp::ICMPv6_ECHO_REPLY));
	pcpp::icmpv6_echo_reply *repData = icmpv6EchoReplyLayer->getEchoReplyData();
	PTF_ASSERT_NOT_NULL(repData);
	PTF_ASSERT_EQUAL(repData->header->code, 0);
	PTF_ASSERT_EQUAL(repData->header->checksum, 0x4c79);
	PTF_ASSERT_EQUAL(repData->header->id, 0x1800);
	PTF_ASSERT_EQUAL(repData->header->sequence, 0x1400);
	PTF_ASSERT_EQUAL(repData->dataLength, 56);
	PTF_ASSERT_EQUAL(repData->data[3], 0x62);

	/* Neighbor solicitation */
	pcpp::IcmpV6Layer *neighSoli = icmpv6NeighSoli.getLayerOfType<pcpp::IcmpV6Layer>();
	PTF_ASSERT_EQUAL(neighSoli->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(neighSoli->getMessageType(), 135);
	PTF_ASSERT_EQUAL(neighSoli->getCode(), 0);
	PTF_ASSERT_EQUAL(neighSoli->getChecksum(), 0xfe98);

	// Neighbor solicitation with source link-layer option
	pcpp::NDPNeighborSolicitationLayer *shouldBeLayer = icmpv6NeighSoli.getLayerOfType<pcpp::NDPNeighborSolicitationLayer>();
	PTF_ASSERT_EQUAL(shouldBeLayer->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(shouldBeLayer->getTargetIP(), pcpp::IPv6Address("fd53:7cb8:383:2::1:117"));
	PTF_ASSERT_FALSE(shouldBeLayer->getNdpOption(pcpp::NDPNeighborOptionTypes::NDP_OPTION_SOURCE_LINK_LAYER).isNull());
	PTF_ASSERT_EQUAL(shouldBeLayer->getLinkLayerAddress(), pcpp::MacAddress("00:54:af:e9:4d:80"));

	/* Neighbor advertisement */
	pcpp::IcmpV6Layer *neighAdv = icmpv6NeighAdv.getLayerOfType<pcpp::IcmpV6Layer>();
	PTF_ASSERT_EQUAL(neighAdv->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(neighAdv->getMessageType(), 136);
	PTF_ASSERT_EQUAL(neighAdv->getCode(), 0);
	PTF_ASSERT_EQUAL(neighAdv->getChecksum(), 0x9abb);

	// Neighbor advertisement with target link-layer option
	pcpp::NDPNeighborAdvertisementLayer *neighAdv2 = icmpv6NeighAdv.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();
	PTF_ASSERT_EQUAL(neighAdv2->getHeaderLen(), 32);
	PTF_ASSERT_TRUE(neighAdv2->getRouterFlag());
	PTF_ASSERT_FALSE(neighAdv2->getUnicastFlag());
	PTF_ASSERT_TRUE(neighAdv2->getOverrideFlag());
	PTF_ASSERT_EQUAL(neighAdv2->getTargetIP(), pcpp::IPv6Address("fe80::c000:54ff:fef5:0"));
	PTF_ASSERT_EQUAL(neighAdv2->getTargetMac(), pcpp::MacAddress("c2:00:54:f5:00:00"));

	// Neighbor advertisement without target link-layer option
	pcpp::NDPNeighborAdvertisementLayer *neighAdv3 = icmpv6NeighAdvNoOpt.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();
	PTF_ASSERT_EQUAL(neighAdv3->getHeaderLen(), 24);
	PTF_ASSERT_FALSE(neighAdv3->getRouterFlag());
	PTF_ASSERT_TRUE(neighAdv3->getUnicastFlag());
	PTF_ASSERT_FALSE(neighAdv3->getOverrideFlag());
	PTF_ASSERT_EQUAL(neighAdv3->getTargetIP(), pcpp::IPv6Address("fe80:ebeb:ebeb::1"));
	PTF_ASSERT_FALSE(neighAdv3->hasTargetMacInfo());
	PTF_ASSERT_EQUAL(neighAdv3->getTargetMac(), pcpp::MacAddress());
}

PTF_TEST_CASE(IcmpV6CreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/IcmpV6_EchoRequest.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/IcmpV6_EchoReply.dat");
	READ_FILE_INTO_BUFFER(3, "PacketExamples/IcmpV6_NeighSoli.dat");
	READ_FILE_INTO_BUFFER(4, "PacketExamples/IcmpV6_NeighAdv.dat");
	READ_FILE_INTO_BUFFER(5, "PacketExamples/IcmpV6_NeighAdvNoOption.dat");

	uint8_t data[56] = {0xbd, 0xce, 0xcb, 0x62, 0x00, 0x00, 0x00, 0x00, 0xf3, 0xa1, 0x09, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
						0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
						0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

	pcpp::EthLayer ethLayer(pcpp::MacAddress("11:22:33:44:55:66"), pcpp::MacAddress("66:55:44:33:22:11"));
	pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address(std::string("fe80::215:5dff:fea5:c4c5")), pcpp::IPv6Address(std::string("fe80::dd05:dae0:74bc:7341")));

	// Echo request creation
	pcpp::Packet echoRequestPacket(1);
	pcpp::ICMPv6EchoRequestLayer echoReqLayer;
	PTF_ASSERT_NOT_NULL(echoReqLayer.setEchoRequestData(0x0018, 0x0014, data, 56));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&ipv6Layer));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&echoReqLayer));
	echoRequestPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(echoRequestPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(echoRequestPacket.getRawPacket()->getRawData()+54, buffer1+54, bufferLength1-54);

	// Echo reply creation
	pcpp::EthLayer ethLayer2(ethLayer);
	pcpp::IPv6Layer ipLayer2(ipv6Layer);
	pcpp::ICMPv6EchoReplyLayer echoRepLayer;
	pcpp::Packet echoReplyPacket(10);
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&ipLayer2));
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&echoRepLayer));
	PTF_ASSERT_NOT_NULL(echoRepLayer.setEchoReplyData(0x0018, 0x0014, data, 56));
	echoReplyPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(echoReplyPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(echoReplyPacket.getRawPacket()->getRawData()+54, buffer2+54, bufferLength2-54);

	// Neighbor solicitation with source link-layer option
	pcpp::Packet neighSoliPacket(100);
	pcpp::IPv6Layer *pIpv6SoliLayer = new pcpp::IPv6Layer(pcpp::IPv6Address("fd53:7cb8:383:4::67"), pcpp::IPv6Address("fd53:7cb8:383:2::1:117"));
	pcpp::NDPNeighborSolicitationLayer *pNdpSoliLayer = new pcpp::NDPNeighborSolicitationLayer(pcpp::IPv6Address("fd53:7cb8:383:2::1:117"), pcpp::MacAddress("00:54:af:e9:4d:80"));
	PTF_ASSERT_TRUE(neighSoliPacket.addLayer(pIpv6SoliLayer, true));
	PTF_ASSERT_TRUE(neighSoliPacket.addLayer(pNdpSoliLayer, true));
	neighSoliPacket.computeCalculateFields();
	PTF_ASSERT_BUF_COMPARE(neighSoliPacket.getRawPacket()->getRawData()+40, buffer3+58, bufferLength3-62); // dat file contains frame with eth + vlan layer (14 + 4 bytes) and  trailing bytes (4 bytes)

	pcpp::NDPNeighborSolicitationLayer *neighSoliLayer = neighSoliPacket.getLayerOfType<pcpp::NDPNeighborSolicitationLayer>();
	PTF_ASSERT_EQUAL(neighSoliLayer->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(neighSoliLayer->getMessageType(), 135);
	PTF_ASSERT_EQUAL(neighSoliLayer->getCode(), 0);
	PTF_ASSERT_EQUAL(neighSoliLayer->getChecksum(), 0xfe98);
	PTF_ASSERT_EQUAL(neighSoliLayer->getTargetIP(), pcpp::IPv6Address("fd53:7cb8:383:2::1:117"));
	PTF_ASSERT_FALSE(neighSoliLayer->getNdpOption(pcpp::NDPNeighborOptionTypes::NDP_OPTION_SOURCE_LINK_LAYER).isNull());
	PTF_ASSERT_EQUAL(neighSoliLayer->getNdpOptionCount(), 1);
	PTF_ASSERT_EQUAL(neighSoliLayer->getLinkLayerAddress(), pcpp::MacAddress("00:54:af:e9:4d:80"));

	// Neighbor advertisement with target link-layer option
	pcpp::Packet neighAdvPacket(100);
	pcpp::IPv6Layer *pIpv6AdvLayer = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::IPv6Address("ff02::1"));
	pcpp::NDPNeighborAdvertisementLayer *pNdpAdvLayer = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::MacAddress("c2:00:54:f5:00:00"), true, false, true);
	PTF_ASSERT_TRUE(neighAdvPacket.addLayer(pIpv6AdvLayer, true));
	PTF_ASSERT_TRUE(neighAdvPacket.addLayer(pNdpAdvLayer, true));
	neighAdvPacket.computeCalculateFields();
	PTF_ASSERT_BUF_COMPARE(neighAdvPacket.getRawPacket()->getRawData()+40, buffer4+54, bufferLength4-54);

	pcpp::NDPNeighborAdvertisementLayer *neighAdvLayer = neighAdvPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();
	PTF_ASSERT_EQUAL(neighAdvLayer->getHeaderLen(), 32);
	PTF_ASSERT_EQUAL(neighAdvLayer->getMessageType(), pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT);
	PTF_ASSERT_EQUAL(neighAdvLayer->getCode(), 0);
	PTF_ASSERT_EQUAL(neighAdvLayer->getChecksum(), 0x9abb);
	PTF_ASSERT_TRUE(neighAdvLayer->getRouterFlag());
	PTF_ASSERT_FALSE(neighAdvLayer->getUnicastFlag());
	PTF_ASSERT_TRUE(neighAdvLayer->getOverrideFlag());
	PTF_ASSERT_EQUAL(neighAdvLayer->getTargetIP(), pcpp::IPv6Address("fe80::c000:54ff:fef5:0"));
	PTF_ASSERT_EQUAL(neighAdvLayer->getTargetMac(), pcpp::MacAddress("c2:00:54:f5:00:00"));

	// Neighbor advertisement without option
	pcpp::Packet neighAdvPacket2(100);
	pcpp::IPv6Layer *pIpv6AdvLayer2 = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80:ebeb:ebeb::1"), pcpp::IPv6Address("fe80:ebeb:ebeb::2"));
	pcpp::NDPNeighborAdvertisementLayer *pNdpAdvLayer2 = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80:ebeb:ebeb::1"), false, true, false);
	PTF_ASSERT_TRUE(neighAdvPacket2.addLayer(pIpv6AdvLayer2, true));
	PTF_ASSERT_TRUE(neighAdvPacket2.addLayer(pNdpAdvLayer2, true));
	neighAdvPacket2.computeCalculateFields();
	PTF_ASSERT_BUF_COMPARE(neighAdvPacket2.getRawPacket()->getRawData()+40, buffer5+54, bufferLength5-58); // dat file contains eth layer (14 bytes) and trailing bytes (4 bytes)

	pcpp::NDPNeighborAdvertisementLayer *neighAdvLayer2 = neighAdvPacket2.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();
	PTF_ASSERT_EQUAL(neighAdvLayer2->getHeaderLen(), 24);
	PTF_ASSERT_EQUAL(neighAdvLayer2->getMessageType(), pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT);
	PTF_ASSERT_EQUAL(neighAdvLayer2->getCode(), 0);
	PTF_ASSERT_EQUAL(neighAdvLayer2->getChecksum(), 0xb49e);
	PTF_ASSERT_FALSE(neighAdvLayer2->getRouterFlag());
	PTF_ASSERT_TRUE(neighAdvLayer2->getUnicastFlag());
	PTF_ASSERT_FALSE(neighAdvLayer2->getOverrideFlag());
	PTF_ASSERT_EQUAL(neighAdvLayer2->getTargetIP(), pcpp::IPv6Address("fe80:ebeb:ebeb::1"));
	PTF_ASSERT_FALSE(neighAdvLayer2->hasTargetMacInfo());
	PTF_ASSERT_EQUAL(neighAdvLayer2->getTargetMac(), pcpp::MacAddress());

	delete [] buffer1;
	delete [] buffer2;
	delete [] buffer3;
	delete [] buffer4;
	delete [] buffer5;
}

PTF_TEST_CASE(IcmpV6EditTest)
{
}
