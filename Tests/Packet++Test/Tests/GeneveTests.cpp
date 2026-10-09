#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "GeneveLayer.h"
#include "IcmpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "EthDot3Layer.h"
#include "MplsLayer.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "RawPacket.h"
#include "Serializers.h"
#include "UdpLayer.h"
#include "VlanLayer.h"

#include <cstring>
#include <memory>
#include <sstream>
#include <vector>

using pcpp_tests::utils::createPacketAndBufferFromHexResource;
using pcpp_tests::utils::createPacketFromHexResource;

PTF_TEST_CASE(GeneveParsingTest)
{
	// GENEVE carrying an Ethernet/IPv4/ICMP packet captured from a Linux kernel tunnel.
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/GeneveICMP.dat");
		pcpp::Packet packet(rawPacket.get());

		auto geneveLayer = packet.getLayerOfType<pcpp::GeneveLayer>();
		PTF_ASSERT_NOT_NULL(geneveLayer);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::Geneve));
		PTF_ASSERT_EQUAL(geneveLayer->getVNI(), 0x000abc);
		PTF_ASSERT_EQUAL(geneveLayer->getProtocolType(), PCPP_ETHERTYPE_ETHBRIDGE);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionsLength(), 0);
		PTF_ASSERT_EQUAL(geneveLayer->getHeaderLen(), 8);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionCount(), 0);
		PTF_ASSERT_FALSE(geneveLayer->getCriticalFlag());
		PTF_ASSERT_FALSE(geneveLayer->getOamFlag());
		auto option = geneveLayer->getFirstOption();
		PTF_ASSERT_TRUE(option.isNull());

		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getProtocol(), pcpp::Ethernet, enum);
		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer()->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer()->getNextLayer()->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getNextLayer()->getNextLayer()->getProtocol(), pcpp::ICMP, enum);
	}

	// GENEVE carrying an Ethernet/IPv4/UDP packet captured from a Linux kernel tunnel.
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/GeneveUDP.dat");
		pcpp::Packet packet(rawPacket.get());

		auto geneveLayer = packet.getLayerOfType<pcpp::GeneveLayer>();
		PTF_ASSERT_NOT_NULL(geneveLayer);
		PTF_ASSERT_EQUAL(geneveLayer->getVNI(), 0x000abc);
		PTF_ASSERT_EQUAL(geneveLayer->getProtocolType(), PCPP_ETHERTYPE_ETHBRIDGE);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionsLength(), 0);
		PTF_ASSERT_EQUAL(geneveLayer->getHeaderLen(), 8);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionCount(), 0);
		PTF_ASSERT_TRUE(geneveLayer->getFirstOption().isNull());
		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getProtocol(), pcpp::Ethernet, enum);
		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer()->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer()->getNextLayer()->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getNextLayer()->getNextLayer()->getProtocol(), pcpp::UDP, enum);
	}

}  // GeneveParsingTest

PTF_TEST_CASE(GeneveCreationTest)
{
	const pcpp::MacAddress outerSource("00:11:22:33:44:55");
	const pcpp::MacAddress outerDestination("66:77:88:99:aa:bb");
	const pcpp::IPv4Address outerSourceIp("192.0.2.1");
	const pcpp::IPv4Address outerDestinationIp("192.0.2.2");
	const pcpp::MacAddress innerSourceMac("10:11:12:13:14:15");
	const pcpp::MacAddress innerDestinationMac("20:21:22:23:24:25");
	const pcpp::IPv4Address innerSourceIp("198.51.100.1");
	const pcpp::IPv4Address innerDestinationIp("198.51.100.2");

	auto parseGeneveInnerLayer = [&](pcpp::Layer* innerLayer, pcpp::Layer* trailingLayer = nullptr,
	                                 uint16_t protocolTypeOverride = 0) {
		pcpp::EthLayer outerEth(outerSource, outerDestination);
		pcpp::IPv4Layer outerIp(outerSourceIp, outerDestinationIp);
		pcpp::UdpLayer outerUdp(12345, pcpp::GeneveLayer::DefaultPort);
		pcpp::GeneveLayer geneveLayer;
		pcpp::Packet craftedPacket(256);
		if (!craftedPacket.addLayer(&outerEth) || !craftedPacket.addLayer(&outerIp) ||
		    !craftedPacket.addLayer(&outerUdp) || !craftedPacket.addLayer(&geneveLayer) ||
		    !craftedPacket.addLayer(innerLayer))
			return pcpp::UnknownProtocol;
		if (trailingLayer != nullptr && !craftedPacket.addLayer(trailingLayer))
			return pcpp::UnknownProtocol;
		craftedPacket.computeCalculateFields();
		if (protocolTypeOverride != 0)
			geneveLayer.setProtocolType(protocolTypeOverride);

		pcpp::RawPacket rawPacket(*craftedPacket.getRawPacket());
		pcpp::Packet parsedPacket(&rawPacket);
		auto parsedGeneve = parsedPacket.getLayerOfType<pcpp::GeneveLayer>();
		if (parsedGeneve == nullptr || parsedGeneve->getNextLayer() == nullptr)
			return pcpp::UnknownProtocol;
		return parsedGeneve->getNextLayer()->getProtocol();
	};

	// Create a GENEVE packet with options and an Ethernet payload.
	{
		const uint8_t optionData[] = { 1, 2, 3, 4, 5 };
		pcpp::GeneveLayer geneveLayer(0xabcdef, PCPP_ETHERTYPE_ETHBRIDGE, true);
		PTF_ASSERT_TRUE(geneveLayer.addOption(0x0102, 3, optionData, sizeof(optionData)));
		PTF_ASSERT_TRUE(geneveLayer.addOption(0x0102, 4, nullptr, 0, true));
		{
			SuppressLogs suppressLogs;
			std::vector<uint8_t> tooLongOptionData(125, 0);
			PTF_ASSERT_FALSE(geneveLayer.addOption(0x0102, 5, tooLongOptionData.data(), tooLongOptionData.size()));
		}
		PTF_ASSERT_EQUAL(geneveLayer.getOptionsLength(), 16);
		PTF_ASSERT_EQUAL(geneveLayer.getHeaderLen(), 24);
		PTF_ASSERT_EQUAL(geneveLayer.getOptionCount(), 2);
		PTF_ASSERT_TRUE(geneveLayer.getCriticalFlag());
		std::ostringstream oss;
		pcpp::JsonSerializer serializer(oss);
		geneveLayer.serialize(serializer);
		PTF_ASSERT_EQUAL(
		    oss.str(),
		    R"({"protocolName":"Geneve","protocolId":66,"length":24,"optionsLength":16,"protocolType":25944,"vni":11259375,"oamFlag":true,"criticalFlag":true,"options":[{"optionClass":258,"type":3,"critical":false,"dataSize":8},{"optionClass":258,"type":4,"critical":true,"dataSize":0}]})");

		pcpp::EthLayer outerEth(outerSource, outerDestination);
		pcpp::IPv4Layer outerIp(outerSourceIp, outerDestinationIp);
		pcpp::UdpLayer outerUdp(12345, pcpp::GeneveLayer::DefaultPort);
		pcpp::EthLayer innerEth(innerSourceMac, innerDestinationMac);
		pcpp::IPv4Layer innerIp(innerSourceIp, innerDestinationIp);
		const uint8_t payloadData[] = { 0xde, 0xad, 0xbe, 0xef };
		pcpp::PayloadLayer payload(payloadData, sizeof(payloadData));

		pcpp::Packet packet(160);
		PTF_ASSERT_TRUE(packet.addLayer(&outerEth));
		PTF_ASSERT_TRUE(packet.addLayer(&outerIp));
		PTF_ASSERT_TRUE(packet.addLayer(&outerUdp));
		PTF_ASSERT_TRUE(packet.addLayer(&geneveLayer));
		PTF_ASSERT_TRUE(packet.addLayer(&innerEth));
		PTF_ASSERT_TRUE(packet.addLayer(&innerIp));
		PTF_ASSERT_TRUE(packet.addLayer(&payload));
		packet.computeCalculateFields();

		PTF_ASSERT_EQUAL(geneveLayer.getProtocolType(), PCPP_ETHERTYPE_ETHBRIDGE);
		PTF_ASSERT_EQUAL(geneveLayer.getVNI(), 0xabcdef);
		PTF_ASSERT_EQUAL(geneveLayer.getHeaderLen(), 24);
		PTF_ASSERT_EQUAL(packet.getLayerOfType<pcpp::GeneveLayer>()->getNextLayer()->getProtocol(), pcpp::Ethernet,
		                 enum);
	}

	// Verify each supported Protocol Type dispatch and the generic fallback.
	{
		pcpp::IPv4Layer ipv4Layer(pcpp::IPv4Address("203.0.113.1"), pcpp::IPv4Address("203.0.113.2"));
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&ipv4Layer), pcpp::IPv4, enum);

		pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address("2001:db8::1"), pcpp::IPv6Address("2001:db8::2"));
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&ipv6Layer), pcpp::IPv6, enum);

		pcpp::ArpLayer arpLayer(pcpp::ArpRequest(innerSourceMac, innerSourceIp, innerDestinationIp));
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&arpLayer), pcpp::ARP, enum);

		pcpp::VlanLayer vlanLayer(10, false, 0, PCPP_ETHERTYPE_IP);
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&vlanLayer), pcpp::VLAN, enum);

		pcpp::MplsLayer mplsLayer(16, 64, 0, true);
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&mplsLayer), pcpp::MPLS, enum);

		const uint8_t dot3PayloadData[] = { 0xde, 0xad, 0xbe, 0xef };
		pcpp::EthDot3Layer dot3Layer(innerSourceMac, innerDestinationMac, sizeof(dot3PayloadData));
		pcpp::PayloadLayer dot3Payload(dot3PayloadData, sizeof(dot3PayloadData));
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&dot3Layer, &dot3Payload), pcpp::EthernetDot3, enum);

		pcpp::PayloadLayer unknownPayload(dot3PayloadData, sizeof(dot3PayloadData));
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&unknownPayload, nullptr, 0x1234), pcpp::GenericPayload, enum);
	}
}  // GeneveCreationTest

PTF_TEST_CASE(GeneveEditTest)
{
	// Edit options and fields on a parsed GENEVE packet.
	{
		auto packetAndBuffer = createPacketAndBufferFromHexResource("PacketExamples/GeneveICMP.dat");
		pcpp::Packet packet(packetAndBuffer.packet.get());
		auto geneveLayer = packet.getLayerOfType<pcpp::GeneveLayer>();
		PTF_ASSERT_NOT_NULL(geneveLayer);
		const uint8_t initialOptionData[] = { 0x11, 0x22, 0x33, 0x44 };
		PTF_ASSERT_TRUE(geneveLayer->addOption(0x0102, 3, initialOptionData, sizeof(initialOptionData), true));

		auto originalLength = packet.getRawPacket()->getRawDataLen();
		PTF_ASSERT_TRUE(geneveLayer->removeOption(0x0102, 3));
		PTF_ASSERT_EQUAL(packet.getRawPacket()->getRawDataLen(), originalLength - 8);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionsLength(), 0);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionCount(), 0);
		PTF_ASSERT_FALSE(geneveLayer->getCriticalFlag());

		const uint8_t replacementData[] = { 0xaa, 0xbb, 0xcc, 0xdd };
		PTF_ASSERT_TRUE(geneveLayer->addOption(0x0102, 7, replacementData, sizeof(replacementData), true));
		PTF_ASSERT_EQUAL(geneveLayer->getOptionsLength(), 8);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionCount(), 1);
		PTF_ASSERT_TRUE(geneveLayer->getCriticalFlag());

		geneveLayer->setVNI(0x10203);
		PTF_ASSERT_EQUAL(geneveLayer->getVNI(), 0x010203);
		geneveLayer->setOamFlag(false);
		PTF_ASSERT_FALSE(geneveLayer->getOamFlag());
		geneveLayer->setOamFlag(true);
		PTF_ASSERT_TRUE(geneveLayer->getOamFlag());
		geneveLayer->setProtocolType(PCPP_ETHERTYPE_IP);
		PTF_ASSERT_EQUAL(geneveLayer->getProtocolType(), PCPP_ETHERTYPE_IP);
		PTF_ASSERT_TRUE(geneveLayer->removeAllOptions());
		PTF_ASSERT_EQUAL(geneveLayer->getOptionsLength(), 0);
		PTF_ASSERT_EQUAL(geneveLayer->getHeaderLen(), 8);
		PTF_ASSERT_FALSE(geneveLayer->getCriticalFlag());
	}

	// Critical flag follows the critical options as they are added and removed.
	{
		pcpp::GeneveLayer criticalFlagLayer;
		PTF_ASSERT_FALSE(criticalFlagLayer.getCriticalFlag());
		PTF_ASSERT_TRUE(criticalFlagLayer.addOption(0x0102, 1, nullptr, 0));
		PTF_ASSERT_FALSE(criticalFlagLayer.getCriticalFlag());
		PTF_ASSERT_TRUE(criticalFlagLayer.addOption(0x0102, 2, nullptr, 0, true));
		PTF_ASSERT_TRUE(criticalFlagLayer.getCriticalFlag());
		PTF_ASSERT_TRUE(criticalFlagLayer.addOption(0x0102, 3, nullptr, 0));
		PTF_ASSERT_TRUE(criticalFlagLayer.getCriticalFlag());
		PTF_ASSERT_TRUE(criticalFlagLayer.removeOption(0x0102, 2));
		PTF_ASSERT_FALSE(criticalFlagLayer.getCriticalFlag());
	}

	// Adding an option with data aliased into the layer remains safe if the layer reallocates.
	{
		pcpp::GeneveLayer aliasedDataLayer;
		const uint8_t aliasedData[] = { 0x10, 0x20, 0x30, 0x40 };
		PTF_ASSERT_TRUE(aliasedDataLayer.addOption(0x0102, 8, aliasedData, sizeof(aliasedData)));
		auto sourceOption = aliasedDataLayer.getFirstOption();
		PTF_ASSERT_TRUE(aliasedDataLayer.addOption(0x0102, 9, sourceOption.getData(), sourceOption.getDataSize()));
		auto copiedOption = aliasedDataLayer.getNextOption(aliasedDataLayer.getFirstOption());
		PTF_ASSERT_FALSE(copiedOption.isNull());
		PTF_ASSERT_BUF_COMPARE(copiedOption.getData(), aliasedData, sizeof(aliasedData));
	}
}  // GeneveEditTest

PTF_TEST_CASE(GeneveEdgeCaseTest)
{
	auto makeOwnedLayer = [](const uint8_t* data, size_t dataLen) {
		auto ownedData = std::make_unique<uint8_t[]>(dataLen);
		std::memcpy(ownedData.get(), data, dataLen);
		return std::unique_ptr<pcpp::GeneveLayer>(
		    new pcpp::GeneveLayer(ownedData.release(), dataLen, nullptr, nullptr));
	};

	// validate fixed-header fields and null-safe option behavior.
	{
		// Raw headers use the on-wire layout: Ver/Opt Len, O/C/Reserved, Protocol Type, VNI, Reserved, then options.
		const uint8_t truncatedHeader[7] = {};
		PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(truncatedHeader, sizeof(truncatedHeader)));

		pcpp::GeneveOption nullOption;
		PTF_ASSERT_TRUE(nullOption.isNull());
		PTF_ASSERT_EQUAL(nullOption.getOptionClass(), 0);
		PTF_ASSERT_EQUAL(nullOption.getType(), 0);
		PTF_ASSERT_FALSE(nullOption.isCritical());
		PTF_ASSERT_EQUAL(nullOption.getDataSize(), 0);
		PTF_ASSERT_EQUAL(nullOption.getTotalSize(), 0);
		PTF_ASSERT_NULL(nullOption.getData());

		uint8_t unsupportedVersion[8] = { 0x40, 0, 0x65, 0x58, 0, 0, 1, 0 };
		PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(unsupportedVersion, sizeof(unsupportedVersion)));
		uint8_t invalidProtocolType[8] = { 0, 0, 0x05, 0xff, 0, 0, 1, 0 };
		PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(invalidProtocolType, sizeof(invalidProtocolType)));
		uint8_t minimumProtocolType[8] = { 0, 0, 0x06, 0, 0, 0, 1, 0 };
		PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(minimumProtocolType, sizeof(minimumProtocolType)));
	}

	// the header-declared options area must fit in the available data.
	{
		const uint8_t truncatedOptionsArea[8] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0 };
		PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(truncatedOptionsArea, sizeof(truncatedOptionsArea)));
	}

	// option traversal stops safely at truncated or malformed options.
	{
		uint8_t truncatedOptions[12] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x03, 1 };
		PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(truncatedOptions, sizeof(truncatedOptions)));
		auto truncatedOptionsLayer = makeOwnedLayer(truncatedOptions, sizeof(truncatedOptions));
		PTF_ASSERT_TRUE(truncatedOptionsLayer->getFirstOption().isNull());

		uint8_t validZeroLengthOption[12] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x03, 0 };
		PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(validZeroLengthOption, sizeof(validZeroLengthOption)));

		uint8_t criticalOptionWithoutFlag[12] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x83, 0 };
		PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(criticalOptionWithoutFlag, sizeof(criticalOptionWithoutFlag)));
		uint8_t criticalOptionWithFlag[12] = { 1, 0x40, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x83, 0 };
		PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(criticalOptionWithFlag, sizeof(criticalOptionWithFlag)));

		uint8_t validAndMalformedOptions[16] = {
			2, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x03, 0, 0x01, 0x02, 0x03, 1
		};
		PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(validAndMalformedOptions, sizeof(validAndMalformedOptions)));
		auto optionsLayer = makeOwnedLayer(validAndMalformedOptions, sizeof(validAndMalformedOptions));
		auto firstOption = optionsLayer->getFirstOption();
		PTF_ASSERT_FALSE(firstOption.isNull());
		PTF_ASSERT_EQUAL(optionsLayer->getOptionCount(), 1);
		PTF_ASSERT_TRUE(optionsLayer->getNextOption(firstOption).isNull());
		PTF_ASSERT_TRUE(optionsLayer->getNextOption(pcpp::GeneveOption()).isNull());
		PTF_ASSERT_FALSE(optionsLayer->getOption(0x0102, 3).isNull());
		PTF_ASSERT_TRUE(optionsLayer->getOption(0x0102, 4).isNull());
	}

	// getNextOption rejects foreign options and options corrupted after retrieval.
	{
		pcpp::GeneveLayer firstLayer;
		pcpp::GeneveLayer secondLayer;
		PTF_ASSERT_TRUE(firstLayer.addOption(0x0102, 1, nullptr, 0));
		PTF_ASSERT_TRUE(secondLayer.addOption(0x0102, 2, nullptr, 0));
		auto foreignOption = firstLayer.getFirstOption();
		PTF_ASSERT_FALSE(foreignOption.isNull());
		PTF_ASSERT_TRUE(secondLayer.getNextOption(foreignOption).isNull());

		pcpp::GeneveLayer malformedCurrentLayer;
		PTF_ASSERT_TRUE(malformedCurrentLayer.addOption(0x0102, 1, nullptr, 0));
		PTF_ASSERT_TRUE(malformedCurrentLayer.addOption(0x0102, 2, nullptr, 0));
		auto malformedCurrent = malformedCurrentLayer.getFirstOption();
		PTF_ASSERT_FALSE(malformedCurrent.isNull());
		malformedCurrentLayer.getData()[11] = 2;
		PTF_ASSERT_TRUE(malformedCurrentLayer.getNextOption(malformedCurrent).isNull());
	}

	// unsupported GENEVE versions fall back to a generic UDP payload.
	{
		pcpp::EthLayer outerEth(pcpp::MacAddress("00:11:22:33:44:55"), pcpp::MacAddress("66:77:88:99:aa:bb"));
		pcpp::IPv4Layer outerIp(pcpp::IPv4Address("192.0.2.1"), pcpp::IPv4Address("192.0.2.2"));
		pcpp::UdpLayer outerUdp(12345, pcpp::GeneveLayer::DefaultPort);
		pcpp::GeneveLayer geneveLayer(1);
		pcpp::EthLayer innerEth(pcpp::MacAddress("10:11:12:13:14:15"), pcpp::MacAddress("20:21:22:23:24:25"));

		pcpp::Packet craftedPacket(96);
		PTF_ASSERT_TRUE(craftedPacket.addLayer(&outerEth));
		PTF_ASSERT_TRUE(craftedPacket.addLayer(&outerIp));
		PTF_ASSERT_TRUE(craftedPacket.addLayer(&outerUdp));
		PTF_ASSERT_TRUE(craftedPacket.addLayer(&geneveLayer));
		PTF_ASSERT_TRUE(craftedPacket.addLayer(&innerEth));
		craftedPacket.computeCalculateFields();

		const auto* rawData = craftedPacket.getRawPacket()->getRawData();
		std::vector<uint8_t> malformedData(rawData, rawData + craftedPacket.getRawPacket()->getRawDataLen());
		const auto geneveOffset = static_cast<size_t>(geneveLayer.getData() - rawData);
		malformedData[geneveOffset] = 0x40;
		timeval timestamp{};
		pcpp::RawPacket malformedRawPacket(malformedData.data(), static_cast<int>(malformedData.size()), timestamp,
		                                   false);
		pcpp::Packet malformedPacket(&malformedRawPacket);
		PTF_ASSERT_NULL(malformedPacket.getLayerOfType<pcpp::GeneveLayer>());
		auto* parsedUdp = malformedPacket.getLayerOfType<pcpp::UdpLayer>();
		PTF_ASSERT_NOT_NULL(parsedUdp);
		PTF_ASSERT_NOT_NULL(parsedUdp->getNextLayer());
		PTF_ASSERT_EQUAL(parsedUdp->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);
	}
}  // GeneveMalformedPacketTest
