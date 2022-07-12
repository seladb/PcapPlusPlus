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

PTF_TEST_CASE(IcmpV6Parsing)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_EchoRequest.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IcmpV6_EchoReply.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/IcmpV6_NeighSoli.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/IcmpV6_NeighAdv.dat");

	pcpp::Packet icmpv6EchoRequest(&rawPacket1);
	pcpp::Packet icmpv6EchoReply(&rawPacket2);
	pcpp::Packet icmpv6NeighSoli(&rawPacket3);
	pcpp::Packet icmpv6NeighAdv(&rawPacket4);

	pcpp::IcmpV6Layer *icmpv6Layer = NULL;

	PTF_ASSERT_TRUE(icmpv6EchoRequest.isPacketOfType(pcpp::ICMPv6));
	PTF_ASSERT_TRUE(icmpv6EchoReply.isPacketOfType(pcpp::ICMPv6));
	PTF_ASSERT_TRUE(icmpv6NeighSoli.isPacketOfType(pcpp::ICMPv6));
	PTF_ASSERT_TRUE(icmpv6NeighAdv.isPacketOfType(pcpp::ICMPv6));

	// Echo request
	icmpv6Layer = icmpv6EchoRequest.getLayerOfType<pcpp::IcmpV6Layer>();
	PTF_ASSERT_NOT_NULL(icmpv6Layer);
	PTF_ASSERT_TRUE(icmpv6Layer->isMessageOfType(pcpp::ICMPv6_ECHO_REQUEST));
	PTF_ASSERT_NULL(icmpv6Layer->getEchoReplyData());
	pcpp::icmpv6_echo_request *reqData = icmpv6Layer->getEchoRequestData();
	PTF_ASSERT_NOT_NULL(reqData);
	PTF_ASSERT_EQUAL(reqData->header->code, 0);
	PTF_ASSERT_EQUAL(reqData->header->checksum, 0x4c7a);
	PTF_ASSERT_EQUAL(reqData->header->id, 0x1800);
	PTF_ASSERT_EQUAL(reqData->header->sequence, 0x1400);
	PTF_ASSERT_EQUAL(reqData->dataLength, 56);
	PTF_ASSERT_EQUAL(reqData->data[3], 0x62);

	// Echo reply
	icmpv6Layer = icmpv6EchoReply.getLayerOfType<pcpp::IcmpV6Layer>();
	PTF_ASSERT_NOT_NULL(icmpv6Layer);
	PTF_ASSERT_TRUE(icmpv6Layer->isMessageOfType(pcpp::ICMPv6_ECHO_REPLY));
	PTF_ASSERT_NULL(icmpv6Layer->getEchoRequestData());
	pcpp::icmpv6_echo_reply *repData = icmpv6Layer->getEchoReplyData();
	PTF_ASSERT_NOT_NULL(repData);
	PTF_ASSERT_EQUAL(repData->header->code, 0);
	PTF_ASSERT_EQUAL(repData->header->checksum, 0x4c79);
	PTF_ASSERT_EQUAL(repData->header->id, 0x1800);
	PTF_ASSERT_EQUAL(repData->header->sequence, 0x1400);
	PTF_ASSERT_EQUAL(repData->dataLength, 56);
	PTF_ASSERT_EQUAL(repData->data[3], 0x62);

	/* Neighbor solicitation */
	pcpp::IcmpV6Layer *neighSoli = icmpv6NeighSoli.getLayerOfType<pcpp::IcmpV6Layer>();
	PTF_ASSERT_EQUAL(neighSoli->getHeaderLen(), 4);
	PTF_ASSERT_EQUAL(neighSoli->getMessageType(), 135);
	PTF_ASSERT_EQUAL(neighSoli->getCode(), 0);
	PTF_ASSERT_EQUAL(neighSoli->getChecksum(), 0xfe98);

	/* Neighbor advertisement */
	pcpp::IcmpV6Layer *neighAdv = icmpv6NeighAdv.getLayerOfType<pcpp::IcmpV6Layer>();
	PTF_ASSERT_EQUAL(neighAdv->getHeaderLen(), 4);
	PTF_ASSERT_EQUAL(neighAdv->getMessageType(), 136);
	PTF_ASSERT_EQUAL(neighAdv->getCode(), 0);
	PTF_ASSERT_EQUAL(neighAdv->getChecksum(), 0x9abb);
}

PTF_TEST_CASE(IcmpV6CreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/IcmpV6_EchoRequest.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/IcmpV6_EchoReply.dat");

	uint8_t data[56] = {0xbd, 0xce, 0xcb, 0x62, 0x00, 0x00, 0x00, 0x00, 0xf3, 0xa1, 0x09, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
						0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
						0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

	pcpp::EthLayer ethLayer(pcpp::MacAddress("11:22:33:44:55:66"), pcpp::MacAddress("66:55:44:33:22:11"));
	pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address(std::string("1111::8888")), pcpp::IPv6Address(std::string("8888::1111")));

	// Echo request creation
	pcpp::Packet echoRequestPacket(1);
	pcpp::IcmpV6Layer echoReqLayer;
	PTF_ASSERT_NOT_NULL(echoReqLayer.setEchoRequestData(0x0018, 0x0014, data, 56));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&ipv6Layer));
	PTF_ASSERT_TRUE(echoRequestPacket.addLayer(&echoReqLayer));
	echoRequestPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(echoRequestPacket.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(echoRequestPacket.getRawPacket()->getRawData()+58, buffer1+58, bufferLength1-58); // start after checksum field

	// Echo reply creation
	pcpp::EthLayer ethLayer2(ethLayer);
	pcpp::IPv6Layer ipLayer2(ipv6Layer);
	pcpp::IcmpV6Layer echoRepLayer;
	pcpp::Packet echoReplyPacket(10);
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&ethLayer2));
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&ipLayer2));
	PTF_ASSERT_TRUE(echoReplyPacket.addLayer(&echoRepLayer));
	PTF_ASSERT_NOT_NULL(echoRepLayer.setEchoReplyData(0x0018, 0x0014, data, 56));
	echoReplyPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(echoReplyPacket.getRawPacket()->getRawDataLen(), bufferLength2);
	PTF_ASSERT_BUF_COMPARE(echoReplyPacket.getRawPacket()->getRawData()+58, buffer2+58, bufferLength2-58); // start after checksum field

	delete [] buffer1;
	delete [] buffer2;
}

PTF_TEST_CASE(IcmpV6Crafting)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_NeighSoli.dat");

	pcpp::Packet icmpPacket(&rawPacket1);

	pcpp::IcmpV6Layer *shouldBeLayer = icmpPacket.getLayerOfType<pcpp::IcmpV6Layer>();

	pcpp::IcmpV6Layer isLayer(pcpp::ICMPv6_NEIGHBOR_SOLICITATION, 0);

	PTF_ASSERT_EQUAL(shouldBeLayer->getHeaderLen(), isLayer.getHeaderLen());
	PTF_ASSERT_EQUAL(shouldBeLayer->getMessageType(), isLayer.getMessageType());
	PTF_ASSERT_EQUAL(shouldBeLayer->getCode(), isLayer.getCode());
}

PTF_TEST_CASE(IcmpV6SolicitationParsing)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_NeighSoli.dat");

	pcpp::Packet icmpPacket(&rawPacket1);
	pcpp::NDPNeighborSolicitationLayer *shouldBeLayer = icmpPacket.getLayerOfType<pcpp::NDPNeighborSolicitationLayer>();

	PTF_ASSERT_EQUAL(shouldBeLayer->getHeaderLen(), 28);
	PTF_ASSERT_EQUAL(shouldBeLayer->getTargetIP(), pcpp::IPv6Address("fd53:7cb8:383:2::1:117"));
	PTF_ASSERT_TRUE(shouldBeLayer->hasLinkLayerAddress());
	PTF_ASSERT_EQUAL(shouldBeLayer->getLinkLayerAddress(), pcpp::MacAddress("00:54:af:e9:4d:80"));
}

PTF_TEST_CASE(IcmpV6SolicitationCrafting)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_NeighSoli.dat");

	pcpp::Packet icmpPacket(&rawPacket1);
	pcpp::IcmpV6Layer *shouldBeIcmpLayer = icmpPacket.getLayerOfType<pcpp::IcmpV6Layer>();
	pcpp::NDPNeighborSolicitationLayer *shouldBeNdpLayer = icmpPacket.getLayerOfType<pcpp::NDPNeighborSolicitationLayer>();

	pcpp::Packet isPacket(100);
	pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fd53:7cb8:383:4::67"), pcpp::IPv6Address("fd53:7cb8:383:2::1:117"));
	pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_SOLICITATION, 0);
	pcpp::NDPNeighborSolicitationLayer *pNdpLayer = new pcpp::NDPNeighborSolicitationLayer(pcpp::IPv6Address("fd53:7cb8:383:2::1:117"), pcpp::MacAddress("00:54:af:e9:4d:80"));

	PTF_ASSERT_TRUE(isPacket.addLayer(pIpv6Layer, true));
	PTF_ASSERT_TRUE(isPacket.addLayer(pIcmpV6Layer, true));
	PTF_ASSERT_TRUE(isPacket.addLayer(pNdpLayer, true));

	isPacket.computeCalculateFields();

	pcpp::IPv6Layer *isIpv6Layer = isPacket.getLayerOfType<pcpp::IPv6Layer>();
	pcpp::IPv6Layer *shouldBeIpv6Layer = icmpPacket.getLayerOfType<pcpp::IPv6Layer>();

	PTF_ASSERT_EQUAL(shouldBeIpv6Layer->getSrcIPAddress(), isIpv6Layer->getSrcIPAddress());
	PTF_ASSERT_EQUAL(shouldBeIpv6Layer->getDstIPAddress(), isIpv6Layer->getDstIPAddress());

	pcpp::IcmpV6Layer *isIcmpLayer = isPacket.getLayerOfType<pcpp::IcmpV6Layer>();
	pcpp::NDPNeighborSolicitationLayer *isNdpLayer = isPacket.getLayerOfType<pcpp::NDPNeighborSolicitationLayer>();

	PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getHeaderLen(), isIcmpLayer->getHeaderLen());
	PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getMessageType(), isIcmpLayer->getMessageType());
	PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getCode(), isIcmpLayer->getCode());
	PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getChecksum(), isIcmpLayer->getChecksum());
	PTF_ASSERT_EQUAL(shouldBeNdpLayer->getHeaderLen(), isNdpLayer->getHeaderLen());
	PTF_ASSERT_EQUAL(shouldBeNdpLayer->getTargetIP(), isNdpLayer->getTargetIP());

	PTF_ASSERT_TRUE(shouldBeNdpLayer->hasLinkLayerAddress());
	PTF_ASSERT_TRUE(isNdpLayer->hasLinkLayerAddress());

	PTF_ASSERT_EQUAL(shouldBeNdpLayer->getLinkLayerAddress(), isNdpLayer->getLinkLayerAddress());
}

PTF_TEST_CASE(IcmpV6AdvertisementParsing)
{
	timeval time;
	gettimeofday(&time, NULL);

	/* Test parsing of advertisement with target link layer option */
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_NeighAdv.dat");

		pcpp::Packet icmpPacket(&rawPacket1);
		pcpp::NDPNeighborAdvertisementLayer *shouldBeLayer = icmpPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		PTF_ASSERT_EQUAL(shouldBeLayer->getHeaderLen(), 28);
		PTF_ASSERT_TRUE(shouldBeLayer->getRouterFlag());
		PTF_ASSERT_FALSE(shouldBeLayer->getUnicastFlag());
		PTF_ASSERT_TRUE(shouldBeLayer->getOverrideFlag());
		PTF_ASSERT_EQUAL(shouldBeLayer->getTargetIP(), pcpp::IPv6Address("fe80::c000:54ff:fef5:0"));
		PTF_ASSERT_EQUAL(shouldBeLayer->getTargetMac(), pcpp::MacAddress("c2:00:54:f5:00:00"));
	}

	/* Test parsing of advertisement without target link layer option */
	{
		READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IcmpV6_NeighAdvNoOption.dat");

		pcpp::Packet icmpPacket(&rawPacket2);
		pcpp::NDPNeighborAdvertisementLayer *shouldBeLayer = icmpPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		PTF_ASSERT_EQUAL(shouldBeLayer->getHeaderLen(), 20);
		PTF_ASSERT_FALSE(shouldBeLayer->getRouterFlag());
		PTF_ASSERT_TRUE(shouldBeLayer->getUnicastFlag());
		PTF_ASSERT_FALSE(shouldBeLayer->getOverrideFlag());
		PTF_ASSERT_EQUAL(shouldBeLayer->getTargetIP(), pcpp::IPv6Address("fe80:ebeb:ebeb::1"));
		PTF_ASSERT_FALSE(shouldBeLayer->hasTargetMacInfo());
		PTF_ASSERT_EQUAL(shouldBeLayer->getTargetMac(), pcpp::MacAddress());
	}
}

PTF_TEST_CASE(IcmpV6AdvertisementCrafting)
{
	timeval time;
	gettimeofday(&time, NULL);

	/* Test crafting of advertisement with target link layer option */
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_NeighAdv.dat");

		pcpp::Packet icmpPacket(&rawPacket1);
		pcpp::IcmpV6Layer *shouldBeIcmpLayer = icmpPacket.getLayerOfType<pcpp::IcmpV6Layer>();
		pcpp::NDPNeighborAdvertisementLayer *shouldBeNdpLayer = icmpPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		pcpp::Packet isPacket(100);
		pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::IPv6Address("ff02::1"));
		pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_ADVERTISEMENT, 0);
		pcpp::NDPNeighborAdvertisementLayer *pNdpLayer = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::MacAddress("c2:00:54:f5:00:00"), true, false, true);

		PTF_ASSERT_TRUE(isPacket.addLayer(pIpv6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pIcmpV6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pNdpLayer, true));

		isPacket.computeCalculateFields();

		pcpp::IPv6Layer *isIpv6Layer = isPacket.getLayerOfType<pcpp::IPv6Layer>();
		pcpp::IPv6Layer *shouldBeIpv6Layer = icmpPacket.getLayerOfType<pcpp::IPv6Layer>();

		PTF_ASSERT_EQUAL(shouldBeIpv6Layer->getSrcIPAddress(), isIpv6Layer->getSrcIPAddress());
		PTF_ASSERT_EQUAL(shouldBeIpv6Layer->getDstIPAddress(), isIpv6Layer->getDstIPAddress());

		pcpp::IcmpV6Layer *isIcmpLayer = isPacket.getLayerOfType<pcpp::IcmpV6Layer>();
		pcpp::NDPNeighborAdvertisementLayer *isNdpLayer = isPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getHeaderLen(), isIcmpLayer->getHeaderLen());
		PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getMessageType(), isIcmpLayer->getMessageType());
		PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getCode(), isIcmpLayer->getCode());
		PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getChecksum(), isIcmpLayer->getChecksum());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getHeaderLen(), isNdpLayer->getHeaderLen());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getRouterFlag(), isNdpLayer->getRouterFlag());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getUnicastFlag(), isNdpLayer->getUnicastFlag());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getOverrideFlag(), isNdpLayer->getOverrideFlag());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getTargetIP(), isNdpLayer->getTargetIP());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getTargetMac(), isNdpLayer->getTargetMac());

		const uint8_t* data = isNdpLayer->getData();
		/* check flags */
		PTF_ASSERT_EQUAL(data[0], 0xa0);
	}

	/* Test crafting of advertisement without target link layer option */
	{
		READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IcmpV6_NeighAdvNoOption.dat");

		pcpp::Packet icmpPacket(&rawPacket2);
		pcpp::IcmpV6Layer *shouldBeIcmpLayer = icmpPacket.getLayerOfType<pcpp::IcmpV6Layer>();
		pcpp::NDPNeighborAdvertisementLayer *shouldBeNdpLayer = icmpPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		pcpp::MacAddress srcMac("c2:00:54:f5:00:00");

		pcpp::Packet isPacket(100);
		pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80:ebeb:ebeb::1"), pcpp::IPv6Address("fe80:ebeb:ebeb::2"));
		pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_ADVERTISEMENT, 0);
		pcpp::NDPNeighborAdvertisementLayer *pNdpLayer = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80:ebeb:ebeb::1"), false, true, false);

		PTF_ASSERT_TRUE(isPacket.addLayer(pIpv6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pIcmpV6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pNdpLayer, true));

		isPacket.computeCalculateFields();

		pcpp::IPv6Layer *isIpv6Layer = isPacket.getLayerOfType<pcpp::IPv6Layer>();
		pcpp::IPv6Layer *shouldBeIpv6Layer = icmpPacket.getLayerOfType<pcpp::IPv6Layer>();

		PTF_ASSERT_EQUAL(shouldBeIpv6Layer->getSrcIPAddress(), isIpv6Layer->getSrcIPAddress());
		PTF_ASSERT_EQUAL(shouldBeIpv6Layer->getDstIPAddress(), isIpv6Layer->getDstIPAddress());

		pcpp::IcmpV6Layer *isIcmpLayer = isPacket.getLayerOfType<pcpp::IcmpV6Layer>();
		pcpp::NDPNeighborAdvertisementLayer *isNdpLayer = isPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getHeaderLen(), isIcmpLayer->getHeaderLen());
		PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getMessageType(), isIcmpLayer->getMessageType());
		PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getCode(), isIcmpLayer->getCode());
		PTF_ASSERT_EQUAL(shouldBeIcmpLayer->getChecksum(), isIcmpLayer->getChecksum());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getHeaderLen(), isNdpLayer->getHeaderLen());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getRouterFlag(), isNdpLayer->getRouterFlag());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getUnicastFlag(), isNdpLayer->getUnicastFlag());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getOverrideFlag(), isNdpLayer->getOverrideFlag());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getTargetIP(), isNdpLayer->getTargetIP());
		PTF_ASSERT_FALSE(shouldBeNdpLayer->hasTargetMacInfo());
		PTF_ASSERT_FALSE(isNdpLayer->hasTargetMacInfo());
		PTF_ASSERT_EQUAL(shouldBeNdpLayer->getTargetMac(), isNdpLayer->getTargetMac());
	}

	// flags tests
	{
		pcpp::Packet isPacket(100);
		pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::IPv6Address("ff02::1"));
		pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_ADVERTISEMENT, 0);
		pcpp::NDPNeighborAdvertisementLayer *pNdpLayer = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::MacAddress("c2:00:54:f5:00:00"), false, false, false);

		PTF_ASSERT_TRUE(isPacket.addLayer(pIpv6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pIcmpV6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pNdpLayer, true));

		isPacket.computeCalculateFields();
		pcpp::NDPNeighborAdvertisementLayer *isNdpLayer = isPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		PTF_ASSERT_FALSE(isNdpLayer->getRouterFlag());
		PTF_ASSERT_FALSE(isNdpLayer->getUnicastFlag());
		PTF_ASSERT_FALSE(isNdpLayer->getOverrideFlag());

		const uint8_t* data = isNdpLayer->getData();
		/* check flags: 0000 0000 */
		PTF_ASSERT_EQUAL(data[0], 0x00);
	}

	{
		pcpp::Packet isPacket(100);
		pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::IPv6Address("ff02::1"));
		pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_ADVERTISEMENT, 0);
		pcpp::NDPNeighborAdvertisementLayer *pNdpLayer = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::MacAddress("c2:00:54:f5:00:00"), true, true, true);

		PTF_ASSERT_TRUE(isPacket.addLayer(pIpv6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pIcmpV6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pNdpLayer, true));

		isPacket.computeCalculateFields();
		pcpp::NDPNeighborAdvertisementLayer *isNdpLayer = isPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		PTF_ASSERT_TRUE(isNdpLayer->getRouterFlag());
		PTF_ASSERT_TRUE(isNdpLayer->getUnicastFlag());
		PTF_ASSERT_TRUE(isNdpLayer->getOverrideFlag());

		const uint8_t* data = isNdpLayer->getData();
		/* check flags: 1110 0000 */
		PTF_ASSERT_EQUAL(data[0], 0xe0);
	}

	{
		pcpp::Packet isPacket(100);
		pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::IPv6Address("ff02::1"));
		pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_ADVERTISEMENT, 0);
		pcpp::NDPNeighborAdvertisementLayer *pNdpLayer = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::MacAddress("c2:00:54:f5:00:00"), false, false, true);

		PTF_ASSERT_TRUE(isPacket.addLayer(pIpv6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pIcmpV6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pNdpLayer, true));

		isPacket.computeCalculateFields();
		pcpp::NDPNeighborAdvertisementLayer *isNdpLayer = isPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		PTF_ASSERT_FALSE(isNdpLayer->getRouterFlag());
		PTF_ASSERT_FALSE(isNdpLayer->getUnicastFlag());
		PTF_ASSERT_TRUE(isNdpLayer->getOverrideFlag());
		const uint8_t* data = isNdpLayer->getData();
		/* check flags: 0010 0000 */
		PTF_ASSERT_EQUAL(data[0], 0x20);
	}

	{
		pcpp::Packet isPacket(100);
		pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::IPv6Address("ff02::1"));
		pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_ADVERTISEMENT, 0);
		pcpp::NDPNeighborAdvertisementLayer *pNdpLayer = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::MacAddress("c2:00:54:f5:00:00"), true, false, false);

		PTF_ASSERT_TRUE(isPacket.addLayer(pIpv6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pIcmpV6Layer, true));
		PTF_ASSERT_TRUE(isPacket.addLayer(pNdpLayer, true));

		isPacket.computeCalculateFields();
		pcpp::NDPNeighborAdvertisementLayer *isNdpLayer = isPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		PTF_ASSERT_TRUE(isNdpLayer->getRouterFlag());
		PTF_ASSERT_FALSE(isNdpLayer->getUnicastFlag());
		PTF_ASSERT_FALSE(isNdpLayer->getOverrideFlag());
		const uint8_t* data = isNdpLayer->getData();
		/* check flags: 1000 0000 */
		PTF_ASSERT_EQUAL(data[0], 0x80);
	}
}
