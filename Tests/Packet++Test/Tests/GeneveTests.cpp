#include "../TestDefinition.h"
#include "ArpLayer.h"
#include "EthLayer.h"
#include "GeneveLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "RawPacket.h"
#include "UdpLayer.h"

#include <vector>

PTF_TEST_CASE(GeneveParsingAndCreationTest)
{
	pcpp::GeneveLayer geneveLayer(0xabcdef, PCPP_ETHERTYPE_ETHBRIDGE, true);
	const uint8_t optionData[] = { 1, 2, 3, 4, 5 };
	PTF_ASSERT_TRUE(geneveLayer.addOption(pcpp::GeneveOptionBuilder(0x0102, 3, optionData, sizeof(optionData))));
	pcpp::GeneveOptionRange firstOptions = geneveLayer.getOptions();
	pcpp::GeneveOptionIterator firstOptionIterator = firstOptions.find(0x0102, 3);
	PTF_ASSERT_TRUE(firstOptionIterator != firstOptions.end());
	pcpp::GeneveOption firstOption = *firstOptionIterator;
	PTF_ASSERT_EQUAL(firstOption.getOptionClass(), 0x0102);
	PTF_ASSERT_EQUAL(firstOption.getType(), 3);
	PTF_ASSERT_FALSE(firstOption.isCritical());
	PTF_ASSERT_EQUAL(firstOption.getDataSize(), 8);
	PTF_ASSERT_BUF_COMPARE(firstOption.getData(), optionData, sizeof(optionData));
	PTF_ASSERT_EQUAL(firstOption.getData()[5], 0);
	PTF_ASSERT_EQUAL(firstOption.getData()[6], 0);
	PTF_ASSERT_EQUAL(firstOption.getData()[7], 0);

	PTF_ASSERT_TRUE(geneveLayer.addOption(pcpp::GeneveOptionBuilder(0x0102, 4, nullptr, 0, true)));
	pcpp::GeneveOptionRange options = geneveLayer.getOptions();
	pcpp::GeneveOptionIterator secondOptionIterator = options.find(0x0102, 4);
	PTF_ASSERT_TRUE(secondOptionIterator != options.end());
	pcpp::GeneveOption secondOption = *secondOptionIterator;
	PTF_ASSERT_TRUE(secondOption.isCritical());
	PTF_ASSERT_EQUAL(geneveLayer.getOptionsLength(), 16);
	PTF_ASSERT_EQUAL(geneveLayer.getHeaderLen(), 24);
	PTF_ASSERT_EQUAL(geneveLayer.getOptionCount(), 2);
	PTF_ASSERT_EQUAL(geneveLayer.getGeneveHeader()->criticalFlag, 1);

	pcpp::EthLayer outerEth(pcpp::MacAddress("00:11:22:33:44:55"), pcpp::MacAddress("66:77:88:99:aa:bb"));
	pcpp::IPv4Layer outerIp(pcpp::IPv4Address("192.0.2.1"), pcpp::IPv4Address("192.0.2.2"));
	pcpp::UdpLayer outerUdp(12345, pcpp::GeneveLayer::DefaultPort);
	pcpp::EthLayer innerEth(pcpp::MacAddress("10:11:12:13:14:15"), pcpp::MacAddress("20:21:22:23:24:25"));
	pcpp::IPv4Layer innerIp(pcpp::IPv4Address("198.51.100.1"), pcpp::IPv4Address("198.51.100.2"));
	const uint8_t payloadData[] = { 0xde, 0xad, 0xbe, 0xef };
	pcpp::PayloadLayer payload(payloadData, sizeof(payloadData));

	pcpp::Packet craftedPacket(128);
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&outerEth));
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&outerIp));
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&outerUdp));
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&geneveLayer));
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&innerEth));
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&innerIp));
	PTF_ASSERT_TRUE(craftedPacket.addLayer(&payload));
	craftedPacket.computeCalculateFields();

	pcpp::RawPacket rawPacket(*craftedPacket.getRawPacket());
	pcpp::Packet parsedPacket(&rawPacket);
	pcpp::GeneveLayer* parsedGeneve = parsedPacket.getLayerOfType<pcpp::GeneveLayer>();
	PTF_ASSERT_NOT_NULL(parsedGeneve);
	PTF_ASSERT_TRUE(parsedPacket.isPacketOfType(pcpp::Geneve));
	PTF_ASSERT_EQUAL(parsedGeneve->getVNI(), 0xabcdef);
	PTF_ASSERT_EQUAL(parsedGeneve->getProtocolType(), PCPP_ETHERTYPE_ETHBRIDGE);
	PTF_ASSERT_EQUAL(parsedGeneve->getGeneveHeader()->oamFlag, 1);
	PTF_ASSERT_EQUAL(parsedGeneve->getGeneveHeader()->criticalFlag, 1);
	PTF_ASSERT_EQUAL(parsedGeneve->getOptionCount(), 2);
	PTF_ASSERT_EQUAL(parsedGeneve->getHeaderLen(), 24);

	pcpp::GeneveOptionRange parsedOptions = parsedGeneve->getOptions();
	pcpp::GeneveOptionIterator parsedFirstOptionIterator = parsedOptions.begin();
	PTF_ASSERT_TRUE(parsedFirstOptionIterator != parsedOptions.end());
	pcpp::GeneveOption parsedFirstOption = *parsedFirstOptionIterator;
	PTF_ASSERT_EQUAL(parsedFirstOption.getOptionClass(), 0x0102);
	PTF_ASSERT_EQUAL(parsedFirstOption.getType(), 3);
	pcpp::GeneveOptionIterator parsedSecondOptionIterator = parsedFirstOptionIterator;
	++parsedSecondOptionIterator;
	PTF_ASSERT_TRUE(parsedSecondOptionIterator != parsedOptions.end());
	pcpp::GeneveOption parsedSecondOption = *parsedSecondOptionIterator;
	PTF_ASSERT_TRUE(parsedSecondOption.isCritical());
	++parsedSecondOptionIterator;
	PTF_ASSERT_TRUE(parsedSecondOptionIterator == parsedOptions.end());
	PTF_ASSERT_EQUAL(parsedGeneve->getNextLayer()->getProtocol(), pcpp::Ethernet, enum);
	PTF_ASSERT_EQUAL(parsedGeneve->getNextLayer()->getNextLayer()->getProtocol(), pcpp::IPv4, enum);

	size_t packetLength = parsedPacket.getRawPacket()->getRawDataLen();
	PTF_ASSERT_TRUE(parsedGeneve->removeOption(0x0102, 4));
	PTF_ASSERT_EQUAL(parsedPacket.getRawPacket()->getRawDataLen(), packetLength - 4);
	PTF_ASSERT_EQUAL(parsedGeneve->getOptionCount(), 1);
	PTF_ASSERT_EQUAL(parsedGeneve->getGeneveHeader()->criticalFlag, 0);
	PTF_ASSERT_TRUE(parsedGeneve->removeAllOptions());
	PTF_ASSERT_EQUAL(parsedGeneve->getOptionsLength(), 0);
	PTF_ASSERT_EQUAL(parsedGeneve->getHeaderLen(), sizeof(pcpp::geneve_header));

	pcpp::EthLayer outerEth2(pcpp::MacAddress("00:11:22:33:44:55"), pcpp::MacAddress("66:77:88:99:aa:bb"));
	pcpp::IPv4Layer outerIp2(pcpp::IPv4Address("192.0.2.1"), pcpp::IPv4Address("192.0.2.2"));
	pcpp::UdpLayer outerUdp2(12346, pcpp::GeneveLayer::DefaultPort);
	pcpp::GeneveLayer ipGeneveLayer;
	pcpp::IPv4Layer directInnerIp(pcpp::IPv4Address("203.0.113.1"), pcpp::IPv4Address("203.0.113.2"));
	pcpp::Packet directIpPacket(96);
	PTF_ASSERT_TRUE(directIpPacket.addLayer(&outerEth2));
	PTF_ASSERT_TRUE(directIpPacket.addLayer(&outerIp2));
	PTF_ASSERT_TRUE(directIpPacket.addLayer(&outerUdp2));
	PTF_ASSERT_TRUE(directIpPacket.addLayer(&ipGeneveLayer));
	PTF_ASSERT_TRUE(directIpPacket.addLayer(&directInnerIp));
	directIpPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipGeneveLayer.getProtocolType(), PCPP_ETHERTYPE_IP);

	pcpp::RawPacket directIpRawPacket(*directIpPacket.getRawPacket());
	pcpp::Packet parsedDirectIpPacket(&directIpRawPacket);
	pcpp::GeneveLayer* parsedIpGeneve = parsedDirectIpPacket.getLayerOfType<pcpp::GeneveLayer>();
	PTF_ASSERT_NOT_NULL(parsedIpGeneve);
	PTF_ASSERT_NOT_NULL(parsedIpGeneve->getNextLayer());
	PTF_ASSERT_EQUAL(parsedIpGeneve->getNextLayer()->getProtocol(), pcpp::IPv4, enum);

	pcpp::EthLayer outerEth3(pcpp::MacAddress("00:11:22:33:44:55"), pcpp::MacAddress("66:77:88:99:aa:bb"));
	pcpp::IPv4Layer outerIp3(pcpp::IPv4Address("192.0.2.1"), pcpp::IPv4Address("192.0.2.2"));
	pcpp::UdpLayer outerUdp3(12347, pcpp::GeneveLayer::DefaultPort);
	pcpp::GeneveLayer arpGeneveLayer;
	pcpp::ArpLayer directInnerArp(pcpp::ArpRequest(
	    pcpp::MacAddress("10:11:12:13:14:15"), pcpp::IPv4Address("198.51.100.1"), pcpp::IPv4Address("198.51.100.2")));
	pcpp::Packet directArpPacket(128);
	PTF_ASSERT_TRUE(directArpPacket.addLayer(&outerEth3));
	PTF_ASSERT_TRUE(directArpPacket.addLayer(&outerIp3));
	PTF_ASSERT_TRUE(directArpPacket.addLayer(&outerUdp3));
	PTF_ASSERT_TRUE(directArpPacket.addLayer(&arpGeneveLayer));
	PTF_ASSERT_TRUE(directArpPacket.addLayer(&directInnerArp));
	directArpPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(arpGeneveLayer.getProtocolType(), PCPP_ETHERTYPE_ARP);

	pcpp::RawPacket directArpRawPacket(*directArpPacket.getRawPacket());
	pcpp::Packet parsedDirectArpPacket(&directArpRawPacket);
	pcpp::GeneveLayer* parsedArpGeneve = parsedDirectArpPacket.getLayerOfType<pcpp::GeneveLayer>();
	PTF_ASSERT_NOT_NULL(parsedArpGeneve);
	PTF_ASSERT_NOT_NULL(parsedArpGeneve->getNextLayer());
	PTF_ASSERT_EQUAL(parsedArpGeneve->getNextLayer()->getProtocol(), pcpp::ARP, enum);
}  // GeneveParsingAndCreationTest

PTF_TEST_CASE(GeneveMalformedPacketTest)
{
	// Raw headers below use the on-wire layout: Ver/Opt Len, O/C/Reserved, Protocol Type, VNI, Reserved,
	// followed by options encoded as Option Class, Type/Critical, and Length.
	// A GENEVE base header is 8 bytes, so this buffer is one byte short.
	const uint8_t truncatedHeader[7] = {};
	PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(truncatedHeader, sizeof(truncatedHeader)));

	// Ver=1 is unsupported; Protocol Type=0x6558 (Transparent Ethernet Bridging) and VNI=1 are valid.
	uint8_t unsupportedVersion[8] = { 0x40, 0, 0x65, 0x58, 0, 0, 1, 0 };
	PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(unsupportedVersion, sizeof(unsupportedVersion)));

	// Opt Len=1 declares a 4-byte options area, but the option's Length=1 requires 4 more data bytes.
	uint8_t truncatedOptions[12] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x03, 1 };
	PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(truncatedOptions, sizeof(truncatedOptions)));

	// Opt Len=1 contains one complete option with Class=0x0102, Type=3, and no option data.
	uint8_t validZeroLengthOption[12] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x03, 0 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(validZeroLengthOption, sizeof(validZeroLengthOption)));

	// 0x05ff is immediately below the EtherType range and is therefore not a valid Protocol Type.
	uint8_t invalidProtocolType[8] = { 0, 0, 0x05, 0xff, 0, 0, 1, 0 };
	PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(invalidProtocolType, sizeof(invalidProtocolType)));
	// 0x0600 is the lower boundary of the EtherType range accepted for Protocol Type.
	uint8_t minimumProtocolType[8] = { 0, 0, 0x06, 0, 0, 0, 1, 0 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(minimumProtocolType, sizeof(minimumProtocolType)));

	// Option Type=0x83 sets the critical bit for Type=3, but the base header C bit remains clear.
	uint8_t criticalOptionWithoutFlag[12] = { 1, 0, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x83, 0 };
	PTF_ASSERT_FALSE(pcpp::GeneveLayer::isDataValid(criticalOptionWithoutFlag, sizeof(criticalOptionWithoutFlag)));
	// The same critical option is valid when 0x40 sets the base header C bit.
	uint8_t criticalOptionWithFlag[12] = { 1, 0x40, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x83, 0 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(criticalOptionWithFlag, sizeof(criticalOptionWithFlag)));
	// C=1 without a critical option is accepted because RFC 8926 only mandates the reverse implication.
	uint8_t flagWithoutCriticalOption[12] = { 1, 0x40, 0x65, 0x58, 0, 0, 1, 0, 0x01, 0x02, 0x03, 0 };
	PTF_ASSERT_TRUE(pcpp::GeneveLayer::isDataValid(flagWithoutCriticalOption, sizeof(flagWithoutCriticalOption)));

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
	// Set Ver=1 in the serialized GENEVE header to verify that UDP parsing falls back to a generic payload.
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
