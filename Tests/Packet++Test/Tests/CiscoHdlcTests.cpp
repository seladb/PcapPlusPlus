#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Packet.h"
#include "CiscoHdlcLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "SystemUtils.h"

using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(CiscoHdlcParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	pcpp_tests::utils::PacketFactory packetFactory(pcpp::LINKTYPE_C_HDLC);

	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/CiscoHDLC-IPv4.dat", packetFactory);

		const pcpp::Packet ciscoHdlcPacket(rawPacket1.get());

		PTF_ASSERT_TRUE(ciscoHdlcPacket.isPacketOfType(pcpp::CiscoHDLC));
		const auto ciscoHdlcLayer = ciscoHdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>();

		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getAddress(), pcpp::CiscoHdlcLayer::AddressType::Unicast, enumclass);
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getHeaderLen(), 4);
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getAddressValue(), 0x0f);
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getNextProtocol(), 0x800);
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->toString(), "Cisco HDLC Layer");
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getNextLayer()->getProtocol(), pcpp::IPv4);
	}

	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/CiscoHDLC-IPv6.dat", packetFactory);

		const pcpp::Packet ciscoHdlcPacket(rawPacket1.get());

		PTF_ASSERT_TRUE(ciscoHdlcPacket.isPacketOfType(pcpp::CiscoHDLC));
		const auto ciscoHdlcLayer = ciscoHdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>();

		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getAddress(), pcpp::CiscoHdlcLayer::AddressType::Unicast, enumclass);
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getNextProtocol(), 0x86dd);
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getNextLayer()->getProtocol(), pcpp::IPv6);
	}

	{
		auto rawPacket1 = createPacketFromHexResource("PacketExamples/CiscoHDLC-SLARP.dat", packetFactory);

		const pcpp::Packet ciscoHdlcPacket(rawPacket1.get());

		PTF_ASSERT_TRUE(ciscoHdlcPacket.isPacketOfType(pcpp::CiscoHDLC));
		const auto ciscoHdlcLayer = ciscoHdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>();

		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getAddress(), pcpp::CiscoHdlcLayer::AddressType::Multicast, enumclass);
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getAddressValue(), 0x8f);
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getNextProtocol(), 0x8035);
		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload);
	}

	// Malformed Cisco HDLC + IPv4
	{
		auto data = std::vector<uint8_t>{ 0x0f, 0x00, 0x08, 0x00, 0x45, 0xc0 };
		auto rawPacket = pcpp::RawPacket(data.data(), data.size(), time, false, pcpp::LINKTYPE_C_HDLC);

		const pcpp::Packet ciscoHdlcPacket(&rawPacket);

		PTF_ASSERT_TRUE(ciscoHdlcPacket.isPacketOfType(pcpp::CiscoHDLC));
		const auto ciscoHdlcLayer = ciscoHdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>();

		PTF_ASSERT_EQUAL(ciscoHdlcLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload);
	}
}  // CiscoHdlcParsingTest

PTF_TEST_CASE(CiscoHdlcLayerCreationTest)
{
	pcpp_tests::utils::PacketFactory packetFactory(pcpp::LINKTYPE_C_HDLC);

	{
		pcpp::CiscoHdlcLayer newHdlcLayer(pcpp::CiscoHdlcLayer::AddressType::Unicast);
		pcpp::IPv4Layer ipv4Layer(pcpp::IPv4Address("100.16.1.2"), pcpp::IPv4Address("100.16.1.1"));

		pcpp::Packet newHdlcPacket(20, pcpp::LINKTYPE_C_HDLC);
		newHdlcPacket.addLayer(&newHdlcLayer);
		newHdlcPacket.addLayer(&ipv4Layer);
		newHdlcPacket.computeCalculateFields();

		auto rawPacket1 = createPacketFromHexResource("PacketExamples/CiscoHDLC-IPv4.dat", packetFactory);

		const pcpp::Packet hdlcPacket(rawPacket1.get());

		const auto hdlcLayer = hdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>();
		PTF_ASSERT_NOT_NULL(hdlcLayer);
		PTF_ASSERT_EQUAL(newHdlcPacket.getRawPacket()->getLinkLayerType(), pcpp::LINKTYPE_C_HDLC);

		PTF_ASSERT_BUF_COMPARE(hdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>()->getData(),
		                       newHdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>()->getData(),
		                       hdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>()->getHeaderLen());
	}

	{
		pcpp::CiscoHdlcLayer newHdlcLayer(pcpp::CiscoHdlcLayer::AddressType::Unicast);
		pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address("2402:f000:1:8e01::5555"),
		                          pcpp::IPv6Address("2607:fcd0:100:2300::b108:2a6b"));

		pcpp::Packet newHdlcPacket(20, pcpp::LINKTYPE_C_HDLC);
		newHdlcPacket.addLayer(&newHdlcLayer);
		newHdlcPacket.addLayer(&ipv6Layer);
		newHdlcPacket.computeCalculateFields();

		auto rawPacket1 = createPacketFromHexResource("PacketExamples/CiscoHDLC-IPv6.dat", packetFactory);

		const pcpp::Packet hdlcPacket(rawPacket1.get());

		const auto hdlcLayer = hdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>();
		PTF_ASSERT_NOT_NULL(hdlcLayer);
		PTF_ASSERT_EQUAL(newHdlcPacket.getRawPacket()->getLinkLayerType(), pcpp::LINKTYPE_C_HDLC);

		PTF_ASSERT_BUF_COMPARE(hdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>()->getData(),
		                       newHdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>()->getData(),
		                       hdlcPacket.getLayerOfType<pcpp::CiscoHdlcLayer>()->getHeaderLen());
	}
}  // CiscoHdlcLayerCreationTest

PTF_TEST_CASE(CiscoHdlcLayerEditTest)
{
	{
		pcpp::CiscoHdlcLayer newHdlcLayer(pcpp::CiscoHdlcLayer::AddressType::Multicast);

		newHdlcLayer.setAddress(pcpp::CiscoHdlcLayer::AddressType::Unicast);
		PTF_ASSERT_EQUAL(newHdlcLayer.getAddress(), pcpp::CiscoHdlcLayer::AddressType::Unicast, enumclass);
	}

	{
		pcpp::CiscoHdlcLayer newHdlcLayer(pcpp::CiscoHdlcLayer::AddressType::Unicast);

		newHdlcLayer.setAddressValue(0x8f);
		PTF_ASSERT_EQUAL(newHdlcLayer.getAddress(), pcpp::CiscoHdlcLayer::AddressType::Multicast, enumclass);
	}

	{
		pcpp::CiscoHdlcLayer newHdlcLayer(pcpp::CiscoHdlcLayer::AddressType::Unicast);

		newHdlcLayer.setAddressValue(0x1);
		PTF_ASSERT_EQUAL(newHdlcLayer.getAddress(), pcpp::CiscoHdlcLayer::AddressType::Unknown, enumclass);
	}

	{
		pcpp::CiscoHdlcLayer newHdlcLayer(pcpp::CiscoHdlcLayer::AddressType::Unicast);

		PTF_ASSERT_RAISES(newHdlcLayer.setAddress(pcpp::CiscoHdlcLayer::AddressType::Unknown), std::invalid_argument,
		                  "Cannot set the address to Address::Unknown");
	}

}  // CiscoHdlcLayerEditTest
