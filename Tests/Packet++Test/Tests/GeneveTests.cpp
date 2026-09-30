#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "GeneveLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "EthDot3Layer.h"
#include "MplsLayer.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "RawPacket.h"
#include "UdpLayer.h"
#include "VlanLayer.h"

#include <cstring>
#include <memory>
#include <vector>

using pcpp_tests::utils::createPacketAndBufferFromHexResource;
using pcpp_tests::utils::createPacketFromHexResource;

namespace
{
	pcpp::ProtocolType parseGeneveInnerLayer(pcpp::Layer* innerLayer, pcpp::Layer* trailingLayer = nullptr,
	                                         uint16_t protocolTypeOverride = 0)
	{
		pcpp::EthLayer outerEth(pcpp::MacAddress("00:11:22:33:44:55"), pcpp::MacAddress("66:77:88:99:aa:bb"));
		pcpp::IPv4Layer outerIp(pcpp::IPv4Address("192.0.2.1"), pcpp::IPv4Address("192.0.2.2"));
		pcpp::UdpLayer outerUdp(12345, pcpp::GeneveLayer::DefaultPort);
		pcpp::GeneveLayer geneveLayer;
		pcpp::Packet craftedPacket(256);
		if (!craftedPacket.addLayer(&outerEth) || !craftedPacket.addLayer(&outerIp) ||
		    !craftedPacket.addLayer(&outerUdp) || !craftedPacket.addLayer(&geneveLayer) ||
		    !craftedPacket.addLayer(innerLayer))
			return pcpp::UnknownProtocol;
		if (trailingLayer != nullptr)
		{
			if (!craftedPacket.addLayer(trailingLayer))
				return pcpp::UnknownProtocol;
		}
		craftedPacket.computeCalculateFields();
		if (protocolTypeOverride != 0)
			geneveLayer.setProtocolType(protocolTypeOverride);

		pcpp::RawPacket rawPacket(*craftedPacket.getRawPacket());
		pcpp::Packet parsedPacket(&rawPacket);
		auto parsedGeneve = parsedPacket.getLayerOfType<pcpp::GeneveLayer>();
		if (parsedGeneve == nullptr || parsedGeneve->getNextLayer() == nullptr)
			return pcpp::UnknownProtocol;
		return parsedGeneve->getNextLayer()->getProtocol();
	}
}  // namespace

PTF_TEST_CASE(GeneveParsingTest)
{
	// GENEVE carrying an Ethernet frame and one critical option.
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/GeneveEthernet.dat");
		pcpp::Packet packet(rawPacket.get());

		auto geneveLayer = packet.getLayerOfType<pcpp::GeneveLayer>();
		PTF_ASSERT_NOT_NULL(geneveLayer);
		PTF_ASSERT_TRUE(packet.isPacketOfType(pcpp::Geneve));
		PTF_ASSERT_EQUAL(geneveLayer->getVNI(), 0x000abc);
		PTF_ASSERT_EQUAL(geneveLayer->getProtocolType(), PCPP_ETHERTYPE_ETHBRIDGE);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionsLength(), 8);
		PTF_ASSERT_EQUAL(geneveLayer->getHeaderLen(), 16);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionCount(), 1);
		PTF_ASSERT_TRUE(geneveLayer->getCriticalFlag());
		PTF_ASSERT_TRUE(geneveLayer->getOamFlag());

		const uint8_t expectedOptionData[] = { 0x11, 0x22, 0x33, 0x44 };
		pcpp::GeneveOption option = geneveLayer->getOption(0x0102, 3);
		PTF_ASSERT_FALSE(option.isNull());
		PTF_ASSERT_EQUAL(option.getOptionClass(), 0x0102);
		PTF_ASSERT_EQUAL(option.getType(), 3);
		PTF_ASSERT_TRUE(option.isCritical());
		PTF_ASSERT_EQUAL(option.getDataSize(), 4);
		PTF_ASSERT_BUF_COMPARE(option.getData(), expectedOptionData, sizeof(expectedOptionData));
		PTF_ASSERT_FALSE(geneveLayer->getFirstOption().isNull());
		PTF_ASSERT_TRUE(geneveLayer->getNextOption(option).isNull());

		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getProtocol(), pcpp::Ethernet, enum);
		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer()->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
	}

	// GENEVE carrying an IPv4 packet without options.
	{
		auto rawPacket = createPacketFromHexResource("PacketExamples/GeneveIPv4.dat");
		pcpp::Packet packet(rawPacket.get());

		auto geneveLayer = packet.getLayerOfType<pcpp::GeneveLayer>();
		PTF_ASSERT_NOT_NULL(geneveLayer);
		PTF_ASSERT_EQUAL(geneveLayer->getVNI(), 0x123456);
		PTF_ASSERT_EQUAL(geneveLayer->getProtocolType(), PCPP_ETHERTYPE_IP);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionsLength(), 0);
		PTF_ASSERT_EQUAL(geneveLayer->getHeaderLen(), 8);
		PTF_ASSERT_EQUAL(geneveLayer->getOptionCount(), 0);
		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getProtocol(), pcpp::IPv4, enum);
		PTF_ASSERT_NOT_NULL(geneveLayer->getNextLayer()->getNextLayer());
		PTF_ASSERT_EQUAL(geneveLayer->getNextLayer()->getNextLayer()->getProtocol(), pcpp::ICMP, enum);
	}

	// Verify each supported Protocol Type dispatch and the generic fallback.
	{
		pcpp::IPv6Layer ipv6Layer(pcpp::IPv6Address("2001:db8::1"), pcpp::IPv6Address("2001:db8::2"));
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&ipv6Layer), pcpp::IPv6, enum);

		pcpp::ArpLayer arpLayer(pcpp::ArpRequest(pcpp::MacAddress("10:11:12:13:14:15"),
		                                         pcpp::IPv4Address("198.51.100.1"), pcpp::IPv4Address("198.51.100.2")));
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&arpLayer), pcpp::ARP, enum);

		pcpp::VlanLayer vlanLayer(10, false, 0, PCPP_ETHERTYPE_IP);
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&vlanLayer), pcpp::VLAN, enum);

		pcpp::MplsLayer mplsLayer(16, 64, 0, true);
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&mplsLayer), pcpp::MPLS, enum);

		const uint8_t dot3PayloadData[] = { 0xde, 0xad, 0xbe, 0xef };
		pcpp::EthDot3Layer dot3Layer(pcpp::MacAddress("10:11:12:13:14:15"), pcpp::MacAddress("20:21:22:23:24:25"),
		                             sizeof(dot3PayloadData));
		pcpp::PayloadLayer dot3Payload(dot3PayloadData, sizeof(dot3PayloadData));
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&dot3Layer, &dot3Payload), pcpp::EthernetDot3, enum);

		pcpp::PayloadLayer unknownPayload(dot3PayloadData, sizeof(dot3PayloadData));
		PTF_ASSERT_EQUAL(parseGeneveInnerLayer(&unknownPayload, nullptr, 0x1234), pcpp::GenericPayload, enum);
	}
}  // GeneveParsingTest

PTF_TEST_CASE(GeneveCreationTest)
{
	const uint8_t optionData[] = { 1, 2, 3, 4, 5 };
	pcpp::GeneveLayer geneveLayer(0xabcdef, PCPP_ETHERTYPE_ETHBRIDGE, true);
	PTF_ASSERT_TRUE(geneveLayer.addOption(0x0102, 3, optionData, sizeof(optionData)));
	PTF_ASSERT_TRUE(geneveLayer.addOption(0x0102, 4, nullptr, 0, true));
	std::vector<uint8_t> tooLongOptionData(125, 0);
	{
		SuppressLogs suppressLogs;
		PTF_ASSERT_FALSE(geneveLayer.addOption(0x0102, 5, tooLongOptionData.data(), tooLongOptionData.size()));
	}
	PTF_ASSERT_EQUAL(geneveLayer.getOptionsLength(), 16);
	PTF_ASSERT_EQUAL(geneveLayer.getHeaderLen(), 24);
	PTF_ASSERT_EQUAL(geneveLayer.getOptionCount(), 2);
	PTF_ASSERT_TRUE(geneveLayer.getCriticalFlag());

	pcpp::EthLayer outerEth(pcpp::MacAddress("00:11:22:33:44:55"), pcpp::MacAddress("66:77:88:99:aa:bb"));
	pcpp::IPv4Layer outerIp(pcpp::IPv4Address("192.0.2.1"), pcpp::IPv4Address("192.0.2.2"));
	pcpp::UdpLayer outerUdp(12345, pcpp::GeneveLayer::DefaultPort);
	pcpp::EthLayer innerEth(pcpp::MacAddress("10:11:12:13:14:15"), pcpp::MacAddress("20:21:22:23:24:25"));
	pcpp::IPv4Layer innerIp(pcpp::IPv4Address("198.51.100.1"), pcpp::IPv4Address("198.51.100.2"));
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
	PTF_ASSERT_EQUAL(packet.getLayerOfType<pcpp::GeneveLayer>()->getNextLayer()->getProtocol(), pcpp::Ethernet, enum);

	// computeCalculateFields derives the protocol type for direct IPv4 and ARP encapsulation too.
	{
		pcpp::GeneveLayer ipGeneveLayer;
		pcpp::IPv4Layer innerIpLayer(pcpp::IPv4Address("203.0.113.1"), pcpp::IPv4Address("203.0.113.2"));
		pcpp::Packet ipPacket(96);
		PTF_ASSERT_TRUE(ipPacket.addLayer(&ipGeneveLayer));
		PTF_ASSERT_TRUE(ipPacket.addLayer(&innerIpLayer));
		ipPacket.computeCalculateFields();
		PTF_ASSERT_EQUAL(ipGeneveLayer.getProtocolType(), PCPP_ETHERTYPE_IP);

		pcpp::GeneveLayer arpGeneveLayer;
		pcpp::ArpLayer innerArpLayer(pcpp::ArpRequest(pcpp::MacAddress("10:11:12:13:14:15"),
		                                              pcpp::IPv4Address("198.51.100.1"),
		                                              pcpp::IPv4Address("198.51.100.2")));
		pcpp::Packet arpPacket(128);
		PTF_ASSERT_TRUE(arpPacket.addLayer(&arpGeneveLayer));
		PTF_ASSERT_TRUE(arpPacket.addLayer(&innerArpLayer));
		arpPacket.computeCalculateFields();
		PTF_ASSERT_EQUAL(arpGeneveLayer.getProtocolType(), PCPP_ETHERTYPE_ARP);
	}
}  // GeneveCreationTest

PTF_TEST_CASE(GeneveEditTest)
{
	auto packetAndBuffer = createPacketAndBufferFromHexResource("PacketExamples/GeneveEthernet.dat");
	pcpp::Packet packet(packetAndBuffer.packet.get());
	auto geneveLayer = packet.getLayerOfType<pcpp::GeneveLayer>();
	PTF_ASSERT_NOT_NULL(geneveLayer);

	const size_t originalLength = packet.getRawPacket()->getRawDataLen();
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
}  // GeneveEditTest

PTF_TEST_CASE(GeneveMalformedPacketTest)
{
	auto makeOwnedLayer = [](const uint8_t* data, size_t dataLen) {
		std::unique_ptr<uint8_t[]> ownedData(new uint8_t[dataLen]);
		memcpy(ownedData.get(), data, dataLen);
		return std::unique_ptr<pcpp::GeneveLayer>(
		    new pcpp::GeneveLayer(ownedData.release(), dataLen, nullptr, nullptr));
	};

	// Raw headers below use the on-wire layout: Ver/Opt Len, O/C/Reserved, Protocol Type, VNI, Reserved,
	// followed by options encoded as Option Class, Type/Critical, and Length.
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

	uint8_t truncatedOptions[12] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x03, 1 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(truncatedOptions, sizeof(truncatedOptions)));
	auto truncatedOptionsLayer = makeOwnedLayer(truncatedOptions, sizeof(truncatedOptions));
	PTF_ASSERT_TRUE(truncatedOptionsLayer->getFirstOption().isNull());

	uint8_t validZeroLengthOption[12] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x03, 0 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(validZeroLengthOption, sizeof(validZeroLengthOption)));

	uint8_t invalidProtocolType[8] = { 0, 0, 0x05, 0xff, 0, 0, 1, 0 };
	PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(invalidProtocolType, sizeof(invalidProtocolType)));
	uint8_t minimumProtocolType[8] = { 0, 0, 0x06, 0, 0, 0, 1, 0 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(minimumProtocolType, sizeof(minimumProtocolType)));

	uint8_t criticalOptionWithoutFlag[12] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x83, 0 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(criticalOptionWithoutFlag, sizeof(criticalOptionWithoutFlag)));
	uint8_t criticalOptionWithFlag[12] = { 1, 0x40, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x83, 0 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(criticalOptionWithFlag, sizeof(criticalOptionWithFlag)));

	uint8_t validAndMalformedOptions[16] = { 2, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x03, 0, 0x01, 0x02, 0x03, 1 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(validAndMalformedOptions, sizeof(validAndMalformedOptions)));
	auto optionsLayer = makeOwnedLayer(validAndMalformedOptions, sizeof(validAndMalformedOptions));
	pcpp::GeneveOption firstOption = optionsLayer->getFirstOption();
	PTF_ASSERT_FALSE(firstOption.isNull());
	PTF_ASSERT_EQUAL(optionsLayer->getOptionCount(), 1);
	PTF_ASSERT_TRUE(optionsLayer->getNextOption(firstOption).isNull());
	PTF_ASSERT_TRUE(optionsLayer->getNextOption(pcpp::GeneveOption()).isNull());
	PTF_ASSERT_FALSE(optionsLayer->getOption(0x0102, 3).isNull());
	PTF_ASSERT_TRUE(optionsLayer->getOption(0x0102, 4).isNull());

	pcpp::GeneveLayer firstLayer;
	pcpp::GeneveLayer secondLayer;
	PTF_ASSERT_TRUE(firstLayer.addOption(0x0102, 1, nullptr, 0));
	PTF_ASSERT_TRUE(secondLayer.addOption(0x0102, 2, nullptr, 0));
	pcpp::GeneveOption foreignOption = firstLayer.getFirstOption();
	PTF_ASSERT_FALSE(foreignOption.isNull());
	PTF_ASSERT_TRUE(secondLayer.getNextOption(foreignOption).isNull());

	pcpp::GeneveLayer malformedCurrentLayer;
	PTF_ASSERT_TRUE(malformedCurrentLayer.addOption(0x0102, 1, nullptr, 0));
	PTF_ASSERT_TRUE(malformedCurrentLayer.addOption(0x0102, 2, nullptr, 0));
	pcpp::GeneveOption malformedCurrent = malformedCurrentLayer.getFirstOption();
	PTF_ASSERT_FALSE(malformedCurrent.isNull());
	malformedCurrentLayer.getData()[11] = 2;
	PTF_ASSERT_TRUE(malformedCurrentLayer.getNextOption(malformedCurrent).isNull());

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

	const uint8_t* rawData = craftedPacket.getRawPacket()->getRawData();
	std::vector<uint8_t> malformedData(rawData, rawData + craftedPacket.getRawPacket()->getRawDataLen());
	constexpr size_t GeneveOffset = sizeof(pcpp::ether_header) + sizeof(pcpp::iphdr) + sizeof(pcpp::udphdr);
	malformedData[GeneveOffset] = 0x40;
	timeval timestamp = {};
	pcpp::RawPacket malformedRawPacket(malformedData.data(), static_cast<int>(malformedData.size()), timestamp, false);
	pcpp::Packet malformedPacket(&malformedRawPacket);
	PTF_ASSERT_NULL(malformedPacket.getLayerOfType<pcpp::GeneveLayer>());
	pcpp::UdpLayer* parsedUdp = malformedPacket.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(parsedUdp);
	PTF_ASSERT_NOT_NULL(parsedUdp->getNextLayer());
	PTF_ASSERT_EQUAL(parsedUdp->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);
}  // GeneveMalformedPacketTest
