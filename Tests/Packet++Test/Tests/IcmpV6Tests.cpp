#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
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

	/* Test parsing of solicitation */
	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_Soli.dat");

		pcpp::Packet icmpPacket(&rawPacket1);

		pcpp::IcmpV6Layer *shouldBeLayer = icmpPacket.getLayerOfType<pcpp::IcmpV6Layer>();

		PTF_ASSERT_EQUAL(shouldBeLayer->getHeaderLen(), 4);
		PTF_ASSERT_EQUAL(shouldBeLayer->getMessageType(), 135);
		PTF_ASSERT_EQUAL(shouldBeLayer->getCode(), 0);
		PTF_ASSERT_EQUAL(shouldBeLayer->getChecksum(), 0xfe98);
	}
	/* Test parsing of advertisement */
	{
		READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IcmpV6_Adv.dat");

		pcpp::Packet icmpPacket(&rawPacket2);

		pcpp::IcmpV6Layer *shouldBeLayer = icmpPacket.getLayerOfType<pcpp::IcmpV6Layer>();

		PTF_ASSERT_EQUAL(shouldBeLayer->getHeaderLen(), 4);
		PTF_ASSERT_EQUAL(shouldBeLayer->getMessageType(), 136);
		PTF_ASSERT_EQUAL(shouldBeLayer->getCode(), 0);
		PTF_ASSERT_EQUAL(shouldBeLayer->getChecksum(), 0x9abb);
	}
}

PTF_TEST_CASE(IcmpV6Crafting)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_Soli.dat");

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

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_Soli.dat");

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

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_Soli.dat");

	pcpp::Packet icmpPacket(&rawPacket1);
	pcpp::IcmpV6Layer *shouldBeIcmpLayer = icmpPacket.getLayerOfType<pcpp::IcmpV6Layer>();
	pcpp::NDPNeighborSolicitationLayer *shouldBeNdpLayer = icmpPacket.getLayerOfType<pcpp::NDPNeighborSolicitationLayer>();

	pcpp::Packet isPacket(100);
	pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fd53:7cb8:383:4::67"), pcpp::IPv6Address("fd53:7cb8:383:2::1:117"));
	pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_SOLICITATION, 0);
	pcpp::NDPNeighborSolicitationLayer *pNdpLayer = new pcpp::NDPNeighborSolicitationLayer(pcpp::IPv6Address("fd53:7cb8:383:2::1:117"), pcpp::MacAddress("00:54:af:e9:4d:80"));

	isPacket.addLayer(pIpv6Layer, true);
	isPacket.addLayer(pIcmpV6Layer, true);
	isPacket.addLayer(pNdpLayer, true);

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
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_Adv.dat");

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
		READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IcmpV6_Adv_no_option.dat");

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
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpV6_Adv.dat");

		pcpp::Packet icmpPacket(&rawPacket1);
		pcpp::IcmpV6Layer *shouldBeIcmpLayer = icmpPacket.getLayerOfType<pcpp::IcmpV6Layer>();
		pcpp::NDPNeighborAdvertisementLayer *shouldBeNdpLayer = icmpPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		pcpp::Packet isPacket(100);
		pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::IPv6Address("ff02::1"));
		pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_ADVERTISEMENT, 0);
		pcpp::NDPNeighborAdvertisementLayer *pNdpLayer = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80::c000:54ff:fef5:0"), pcpp::MacAddress("c2:00:54:f5:00:00"), true, false, true);

		isPacket.addLayer(pIpv6Layer, true);
		isPacket.addLayer(pIcmpV6Layer, true);
		isPacket.addLayer(pNdpLayer, true);

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
		READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IcmpV6_Adv_no_option.dat");

		pcpp::Packet icmpPacket(&rawPacket2);
		pcpp::IcmpV6Layer *shouldBeIcmpLayer = icmpPacket.getLayerOfType<pcpp::IcmpV6Layer>();
		pcpp::NDPNeighborAdvertisementLayer *shouldBeNdpLayer = icmpPacket.getLayerOfType<pcpp::NDPNeighborAdvertisementLayer>();

		pcpp::MacAddress srcMac("c2:00:54:f5:00:00");

		pcpp::Packet isPacket(100);
		pcpp::IPv6Layer *pIpv6Layer = new pcpp::IPv6Layer(pcpp::IPv6Address("fe80:ebeb:ebeb::1"), pcpp::IPv6Address("fe80:ebeb:ebeb::2"));
		pcpp::IcmpV6Layer *pIcmpV6Layer = new pcpp::IcmpV6Layer(pcpp::ICMPv6_NEIGHBOR_ADVERTISEMENT, 0);
		pcpp::NDPNeighborAdvertisementLayer *pNdpLayer = new pcpp::NDPNeighborAdvertisementLayer(pcpp::IPv6Address("fe80:ebeb:ebeb::1"), false, true, false);

		isPacket.addLayer(pIpv6Layer, true);
		isPacket.addLayer(pIcmpV6Layer, true);
		isPacket.addLayer(pNdpLayer, true);

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

		isPacket.addLayer(pIpv6Layer, true);
		isPacket.addLayer(pIcmpV6Layer, true);
		isPacket.addLayer(pNdpLayer, true);

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

		isPacket.addLayer(pIpv6Layer, true);
		isPacket.addLayer(pIcmpV6Layer, true);
		isPacket.addLayer(pNdpLayer, true);

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

		isPacket.addLayer(pIpv6Layer, true);
		isPacket.addLayer(pIcmpV6Layer, true);
		isPacket.addLayer(pNdpLayer, true);

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

		isPacket.addLayer(pIpv6Layer, true);
		isPacket.addLayer(pIcmpV6Layer, true);
		isPacket.addLayer(pNdpLayer, true);

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
