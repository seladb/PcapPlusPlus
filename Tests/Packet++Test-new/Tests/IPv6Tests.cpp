#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "IpAddress.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include "../TestDefinition.h"

PTF_TEST_CASE(IPv6UdpPacketParseAndCreate)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv6UdpPacket.dat");

	pcpp::Packet ip6UdpPacket(&rawPacket1);
	PTF_ASSERT(!ip6UdpPacket.isPacketOfType(pcpp::IPv4), "Packet is of type IPv4 instead IPv6");
	PTF_ASSERT(!ip6UdpPacket.isPacketOfType(pcpp::TCP), "Packet is of type TCP where it shouldn't");
	pcpp::IPv6Layer* ipv6Layer = NULL;
	PTF_ASSERT((ipv6Layer = ip6UdpPacket.getLayerOfType<pcpp::IPv6Layer>()) != NULL, "IPv6 layer doesn't exist");
	PTF_ASSERT(ipv6Layer->getIPv6Header()->nextHeader == 17, "Protocol read from packet isnt UDP (17). Protocol is: %d", ipv6Layer->getIPv6Header()->nextHeader);
	PTF_ASSERT(ipv6Layer->getIPv6Header()->ipVersion == 6, "IP version isn't 6. Version is: %d", ipv6Layer->getIPv6Header()->ipVersion);
	pcpp::IPv6Address srcIP(std::string("fe80::4dc7:f593:1f7b:dc11"));
	pcpp::IPv6Address dstIP(std::string("ff02::c"));
	PTF_ASSERT(ipv6Layer->getSrcIpAddress() == srcIP, "incorrect source address");
	PTF_ASSERT(ipv6Layer->getDstIpAddress() == dstIP, "incorrect dest address");
	pcpp::UdpLayer* pUdpLayer = NULL;
	PTF_ASSERT((pUdpLayer = ip6UdpPacket.getLayerOfType<pcpp::UdpLayer>()) != NULL, "UDP layer doesn't exist");
	PTF_ASSERT(pUdpLayer->getUdpHeader()->portDst == htobe16(1900), "UDP dest port != 1900");
	PTF_ASSERT(pUdpLayer->getUdpHeader()->portSrc == htobe16(63628), "UDP dest port != 63628");
	PTF_ASSERT(pUdpLayer->getUdpHeader()->length == htobe16(154), "UDP dest port != 154");
	PTF_ASSERT(pUdpLayer->getUdpHeader()->headerChecksum == htobe16(0x5fea), "UDP dest port != 0x5fea");

	pcpp::Packet ip6UdpPacketNew(1);
	pcpp::EthLayer ethLayer(pcpp::MacAddress("6c:f0:49:b2:de:6e"), pcpp::MacAddress ("33:33:00:00:00:0c"));

	pcpp::IPv6Layer ip6Layer(srcIP, dstIP);
	pcpp::ip6_hdr* ip6Header = ip6Layer.getIPv6Header();
	ip6Header->hopLimit = 1;
	ip6Header->nextHeader = 17;

	pcpp::UdpLayer udpLayer(63628, 1900);

	pcpp::Layer* afterIpv6Layer = pUdpLayer->getNextLayer();
	uint8_t* payloadData = new uint8_t[afterIpv6Layer->getDataLen()];
	afterIpv6Layer->copyData(payloadData);
	pcpp::PayloadLayer payloadLayer(payloadData, afterIpv6Layer->getDataLen(), true);

	PTF_ASSERT(ip6UdpPacketNew.addLayer(&ethLayer), "Couldn't add eth layer");
	PTF_ASSERT(ip6UdpPacketNew.addLayer(&ip6Layer), "Couldn't add IPv6 layer");
	PTF_ASSERT(ip6UdpPacketNew.addLayer(&udpLayer), "Couldn't add udp layer");
	PTF_ASSERT(ip6UdpPacketNew.addLayer(&payloadLayer), "Couldn't add payload layer");
	ip6UdpPacketNew.computeCalculateFields();

	PTF_ASSERT(bufferLength1 == ip6UdpPacketNew.getRawPacket()->getRawDataLen(), "Generated packet len (%d) is different than read packet len (%d)", ip6UdpPacketNew.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT(memcmp(ip6UdpPacketNew.getRawPacket()->getRawData(), buffer1, bufferLength1) == 0, "Raw packet data is different than expected");

	delete[] payloadData;
} // IPv6UdpPacketParseAndCreate



PTF_TEST_CASE(IPv6FragmentationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv6Frag1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IPv6Frag2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/IPv6Frag3.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/IPv6Frag4.dat");

	pcpp::Packet frag1(&rawPacket1);
	pcpp::Packet frag2(&rawPacket2);
	pcpp::Packet frag3(&rawPacket3);
	pcpp::Packet frag4(&rawPacket4);

	pcpp::IPv6Layer* ipv6Layer = frag1.getLayerOfType<pcpp::IPv6Layer>();
	pcpp::IPv6FragmentationHeader* fragHeader = ipv6Layer->getExtensionOfType<pcpp::IPv6FragmentationHeader>();
	PTF_ASSERT(fragHeader->getExtensionType() == pcpp::IPv6Extension::IPv6Fragmentation, "Frag1 extension type isn't IPv6Fragmentation");
	PTF_ASSERT(fragHeader != NULL, "Frag1 - can't retrieve frag header");
	PTF_ASSERT(fragHeader->isFirstFragment() == true, "Frag1 isn't first fragment");
	PTF_ASSERT(fragHeader->isLastFragment() == false, "Frag1 is marked as last fragment");
	PTF_ASSERT(fragHeader->getFragmentOffset() == 0, "Frag1 offset isn't 0");
	PTF_ASSERT(be32toh(fragHeader->getFragHeader()->id) == 0xf88eb466, "Frag1 frag id isn't as expected");
	PTF_ASSERT(fragHeader->getFragHeader()->nextHeader == pcpp::PACKETPP_IPPROTO_UDP, "Frag1 next header isn't UDP, it's %d", fragHeader->getFragHeader()->nextHeader);

	ipv6Layer = frag2.getLayerOfType<pcpp::IPv6Layer>();
	fragHeader = ipv6Layer->getExtensionOfType<pcpp::IPv6FragmentationHeader>();
	PTF_ASSERT(fragHeader->getExtensionType() == pcpp::IPv6Extension::IPv6Fragmentation, "Frag2 extension type isn't IPv6Fragmentation");
	PTF_ASSERT(fragHeader != NULL, "Frag2 - can't retrieve frag header");
	PTF_ASSERT(fragHeader->isFirstFragment() == false, "Frag2 is marked as first fragment");
	PTF_ASSERT(fragHeader->isLastFragment() == false, "Frag2 is marked as last fragment");
	PTF_ASSERT(fragHeader->getFragmentOffset() == 1448, "Frag2 offset isn't 1448");
	PTF_ASSERT(be32toh(fragHeader->getFragHeader()->id) == 0xf88eb466, "Frag2 frag id isn't as expected");
	PTF_ASSERT(fragHeader->getFragHeader()->nextHeader == pcpp::PACKETPP_IPPROTO_UDP, "Frag2 next header isn't UDP");

	ipv6Layer = frag3.getLayerOfType<pcpp::IPv6Layer>();
	fragHeader = ipv6Layer->getExtensionOfType<pcpp::IPv6FragmentationHeader>();
	PTF_ASSERT(fragHeader->getExtensionType() == pcpp::IPv6Extension::IPv6Fragmentation, "Frag3 extension type isn't IPv6Fragmentation");
	PTF_ASSERT(fragHeader != NULL, "Frag3 - can't retrieve frag header");
	PTF_ASSERT(fragHeader->isFirstFragment() == false, "Frag3 is marked as first fragment");
	PTF_ASSERT(fragHeader->isLastFragment() == false, "Frag3 is marked as last fragment");
	PTF_ASSERT(fragHeader->getFragmentOffset() == 2896, "Frag3 offset isn't 2896");
	PTF_ASSERT(be32toh(fragHeader->getFragHeader()->id) == 0xf88eb466, "Frag3 frag id isn't as expected");
	PTF_ASSERT(fragHeader->getFragHeader()->nextHeader == pcpp::PACKETPP_IPPROTO_UDP, "Frag3 next header isn't UDP");

	ipv6Layer = frag4.getLayerOfType<pcpp::IPv6Layer>();
	PTF_ASSERT(ipv6Layer->getHeaderLen() == 48, "Frag4 IPv6 layer len isn't 48");
	fragHeader = ipv6Layer->getExtensionOfType<pcpp::IPv6FragmentationHeader>();
	PTF_ASSERT(fragHeader->getExtensionType() == pcpp::IPv6Extension::IPv6Fragmentation, "Frag4 extension type isn't IPv6Fragmentation");
	PTF_ASSERT(fragHeader != NULL, "Frag4 - can't retrieve frag header");
	PTF_ASSERT(fragHeader->isFirstFragment() == false, "Frag4 is marked as first fragment");
	PTF_ASSERT(fragHeader->isLastFragment() == true, "Frag4 isn't last fragment");
	PTF_ASSERT(fragHeader->getFragmentOffset() == 4344, "Frag4 offset isn't 4344");
	PTF_ASSERT(be32toh(fragHeader->getFragHeader()->id) == 0xf88eb466, "Frag4 frag id isn't as expected");
	PTF_ASSERT(fragHeader->getFragHeader()->nextHeader == pcpp::PACKETPP_IPPROTO_UDP, "Frag4 next header isn't UDP");

	pcpp::EthLayer newEthLayer(*frag1.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer(*frag1.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT(newIPv6Layer.getHeaderLen() == 48, "New IPv6 layer len with old extensions isn't 48");
	newIPv6Layer.removeAllExtensions();
	PTF_ASSERT(newIPv6Layer.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	pcpp::PayloadLayer newPayloadLayer(*frag4.getLayerOfType<pcpp::PayloadLayer>());

	pcpp::Packet newFrag;
	newFrag.addLayer(&newEthLayer);
	newFrag.addLayer(&newIPv6Layer);
	newFrag.addLayer(&newPayloadLayer);

	pcpp::IPv6FragmentationHeader newFragHeader(0xf88eb466, 4344, true);
	newIPv6Layer.addExtension<pcpp::IPv6FragmentationHeader>(newFragHeader);
	PTF_ASSERT(newIPv6Layer.getHeaderLen() == 48, "New IPv6 layer len with new frag extension isn't 48");

	newFrag.computeCalculateFields();

	PTF_ASSERT(frag4.getRawPacket()->getRawDataLen() == newFrag.getRawPacket()->getRawDataLen(), "Generated fragment len (%d) is different than frag4 len (%d)", newFrag.getRawPacket()->getRawDataLen(), frag4.getRawPacket()->getRawDataLen());
	PTF_ASSERT(memcmp(frag4.getRawPacket()->getRawData(), newFrag.getRawPacket()->getRawData(), frag4.getRawPacket()->getRawDataLen()) == 0, "Raw packet data is different than expected");
} // IPv6FragmentationTest



PTF_TEST_CASE(IPv6ExtensionsTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ipv6_options_destination.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/ipv6_options_hop_by_hop.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/ipv6_options_routing1.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/ipv6_options_routing2.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/ipv6_options_ah.dat");
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/ipv6_options_multi.dat");

	pcpp::Packet ipv6Dest(&rawPacket1);
	pcpp::Packet ipv6HopByHop(&rawPacket2);
	pcpp::Packet ipv6Routing1(&rawPacket3);
	pcpp::Packet ipv6Routing2(&rawPacket4);
	pcpp::Packet ipv6AuthHdr(&rawPacket5);
	pcpp::Packet ipv6MultipleOptions(&rawPacket6);


	// parsing of Destionation extension
	pcpp::IPv6Layer* ipv6Layer = ipv6Dest.getLayerOfType<pcpp::IPv6Layer>();
	PTF_ASSERT(ipv6Layer->getExtensionCount() == 1, "Dest ext packet1: num of extensions isn't 1");
	pcpp::IPv6HopByHopHeader* hopByHopExt = ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>();
	pcpp::IPv6DestinationHeader* destExt = ipv6Layer->getExtensionOfType<pcpp::IPv6DestinationHeader>();
	PTF_ASSERT(hopByHopExt == NULL, "Dest ext packet: Found Hop-By-Hop extension although it doesn't exist");
	PTF_ASSERT(destExt != NULL, "Dest ext packet: Cannot find dest extension");
	PTF_ASSERT(destExt->getExtensionType() == pcpp::IPv6Extension::IPv6Destination, "Dest ext packet: Dest ext type isn't IPv6Extension::IPv6Destination");
	PTF_ASSERT(destExt->getOptionCount() == 2, "Dest ext packet: Number of options isn't 2");
	pcpp::IPv6TLVOptionHeader::IPv6Option option = destExt->getFirstOption();
	PTF_ASSERT(option.isNull() == false, "Dest ext packet: First option is null");
	PTF_ASSERT(option.getType() == 11, "Dest ext packet: First option type isn't 11");
	PTF_ASSERT(option.getTotalSize() == 3, "Dest ext packet: First option total size isn't 3");
	PTF_ASSERT(option.getDataSize() == 1, "Dest ext packet: First option data size isn't 1");
	PTF_ASSERT(option.getValueAs<uint8_t>() == 9, "Dest ext packet: First option data isn't 9");
	option = destExt->getNextOption(option);
	PTF_ASSERT(option.isNull() == false, "Dest ext packet: Second option is null");
	PTF_ASSERT(option.getType() == 1, "Dest ext packet: Second option type isn't 1");
	PTF_ASSERT(option.getTotalSize() == 3, "Dest ext packet: Second option total size isn't 3");
	PTF_ASSERT(option.getDataSize() == 1, "Dest ext packet: Second option data size isn't 1");
	PTF_ASSERT(option.getValueAs<uint8_t>() == 0, "Dest ext packet: Second option data isn't 0");
	option = destExt->getNextOption(option);
	PTF_ASSERT(option.isNull() == true, "Dest ext packet: Found third option");
	option = destExt->getOption(11);
	PTF_ASSERT(option.isNull() == false, "Dest ext packet: Cannot find option with type 11");
	PTF_ASSERT(option.getTotalSize() == 3, "Dest ext packet: Option with type 11 total size isn't 3");
	PTF_ASSERT(destExt->getOption(12).isNull() == true, "Dest ext packet: Found option with type 12");
	PTF_ASSERT(destExt->getOption(0).isNull() == true, "Dest ext packet: Found option with type 0");


	// parsing of Hop-By-Hop extension
	ipv6Layer = ipv6HopByHop.getLayerOfType<pcpp::IPv6Layer>();
	hopByHopExt = ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>();
	destExt = ipv6Layer->getExtensionOfType<pcpp::IPv6DestinationHeader>();
	PTF_ASSERT(destExt == NULL, "Hop-By-Hop ext packet: Found dest extension although it doesn't exist");
	PTF_ASSERT(hopByHopExt != NULL, "Hop-By-Hop ext packet: Cannot find Hop-By-Hop extension");
	PTF_ASSERT(hopByHopExt->getExtensionType() == pcpp::IPv6Extension::IPv6HopByHop, "Hop-By-Hop ext packet: Hop-By-Hop ext type isn't IPv6Extension::IPv6HopByHop");
	PTF_ASSERT(hopByHopExt->getOptionCount() == 2, "Hop-By-Hop ext packet: Number of options isn't 2");
	PTF_ASSERT(hopByHopExt->getOption(3).isNull() == true, "Hop-By-Hop ext packet: Found option with type 3");
	PTF_ASSERT(hopByHopExt->getOption(0).isNull() == true, "Hop-By-Hop ext packet: Found option with type 0");
	option = hopByHopExt->getFirstOption();
	PTF_ASSERT(option.getType() == 5, "Hop-By-Hop ext packet: First option type isn't 5");
	PTF_ASSERT(option.getTotalSize() == 4, "Hop-By-Hop ext packet: First option total size isn't 4");
	PTF_ASSERT(option.getDataSize() == 2, "Hop-By-Hop ext packet: First option data size isn't 2");
	PTF_ASSERT(option.getValueAs<uint16_t>() == (uint16_t)0, "Hop-By-Hop ext packet: First option data isn't 0");
	option = hopByHopExt->getNextOption(option);
	PTF_ASSERT(option.isNull() == false, "Hop-By-Hop ext packet: Second option is null");
	PTF_ASSERT(option.getType() == 1, "Hop-By-Hop ext packet: Second option type isn't 1");
	PTF_ASSERT(option.getTotalSize() == 2, "Hop-By-Hop ext packet: Second option total size isn't 2");
	PTF_ASSERT(option.getDataSize() == 0, "Hop-By-Hop ext packet: Second option data size isn't 0");
	PTF_ASSERT(option.getValueAs<uint8_t>() == 0, "Hop-By-Hop ext packet: Second option data isn't 0");
	option = hopByHopExt->getNextOption(option);
	PTF_ASSERT(option.isNull() == true, "Hop-By-Hop ext packet: Found third option");


	// parsing of routing extension #1
	ipv6Layer = ipv6Routing1.getLayerOfType<pcpp::IPv6Layer>();
	hopByHopExt = ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>();
	PTF_ASSERT(ipv6Layer->getExtensionCount() == 1, "Routing ext packet1: num of extensions isn't 1");
	pcpp::IPv6RoutingHeader* routingExt = ipv6Layer->getExtensionOfType<pcpp::IPv6RoutingHeader>();
	PTF_ASSERT(destExt == NULL, "Routing ext packet1: Found dest extension although it doesn't exist");
	PTF_ASSERT(routingExt != NULL, "Routing ext packet1: Cannot find routing extension");
	PTF_ASSERT(routingExt->getExtensionType() == pcpp::IPv6Extension::IPv6Routing, "Routing ext packet1: routing ext isn't of type IPv6Extension::IPv6Routing");
	PTF_ASSERT(routingExt->getRoutingHeader()->routingType == 0, "Routing ext packet1: routing type isn't 0");
	PTF_ASSERT(routingExt->getRoutingHeader()->segmentsLeft == 2, "Routing ext packet1: segments left isn't 2");
	PTF_ASSERT(routingExt->getRoutingAdditionalDataLength() == 36, "Routing ext packet1: additional data len isn't 36");
	PTF_ASSERT(routingExt->getRoutingAdditionalDataAsIPv6Address(4) == pcpp::IPv6Address(std::string("2200::210:2:0:0:4")), "Routing ext packet1: IPv6 address is wrong");
	PTF_ASSERT(routingExt->getRoutingAdditionalDataAsIPv6Address(20) == pcpp::IPv6Address(std::string("2200::240:2:0:0:4")), "Routing ext packet1: second IPv6 address is wrong");


	// parsing of routing extension #2
	ipv6Layer = ipv6Routing2.getLayerOfType<pcpp::IPv6Layer>();
	routingExt = ipv6Layer->getExtensionOfType<pcpp::IPv6RoutingHeader>();
	PTF_ASSERT(routingExt != NULL, "Routing ext packet2: Cannot find routing extension");
	PTF_ASSERT(routingExt->getExtensionType() == pcpp::IPv6Extension::IPv6Routing, "Routing ext packet2: routing ext isn't of type IPv6Extension::IPv6Routing");
	PTF_ASSERT(routingExt->getRoutingHeader()->routingType == 0, "Routing ext packet2: routing type isn't 0");
	PTF_ASSERT(routingExt->getRoutingHeader()->segmentsLeft == 1, "Routing ext packet2: segments left isn't 1");
	PTF_ASSERT(routingExt->getRoutingAdditionalDataLength() == 20, "Routing ext packet2: additional data len isn't 20");
	PTF_ASSERT(routingExt->getRoutingAdditionalDataAsIPv6Address(4) == pcpp::IPv6Address(std::string("2200::210:2:0:0:4")), "Routing ext packet2: IPv6 address is wrong");
	PTF_ASSERT(routingExt->getRoutingAdditionalDataAsIPv6Address(20) == pcpp::IPv6Address::Zero, "Routing ext packet2: additional data out-of-bounds but isn't returned as zero IPv6 address");


	// parsing of authentication header extension
	ipv6Layer = ipv6AuthHdr.getLayerOfType<pcpp::IPv6Layer>();
	pcpp::IPv6AuthenticationHeader* authHdrExt = ipv6Layer->getExtensionOfType<pcpp::IPv6AuthenticationHeader>();
	PTF_ASSERT(authHdrExt != NULL, "AH ext packet: Cannot find AH extension");
	PTF_ASSERT(authHdrExt->getExtensionType() == pcpp::IPv6Extension::IPv6AuthenticationHdr, "AH ext packet: AH ext isn't of type IPv6Extension::IPv6AuthenticationHdr");
	PTF_ASSERT(authHdrExt->getAuthHeader()->securityParametersIndex == htobe32(0x100), "AH ext packet: SPI isn't 0x100");
	PTF_ASSERT(authHdrExt->getAuthHeader()->sequenceNumber == htobe32(32), "AH ext packet: sequence isn't 32");
	PTF_ASSERT(authHdrExt->getIntegrityCheckValueLength() == 12, "AH ext packet: ICV len isn't 12");
	uint8_t expectedICV[12] = { 0x35, 0x48, 0x21, 0x48, 0xb2, 0x43, 0x5a, 0x23, 0xdc, 0xdd, 0x55, 0x36 };
	PTF_ASSERT(memcmp(expectedICV, authHdrExt->getIntegrityCheckValue(), authHdrExt->getIntegrityCheckValueLength()) == 0, "AH ext packet: ICV value isn't as expected");


	// parsing of multiple options in one IPv6 layer
	ipv6Layer = ipv6MultipleOptions.getLayerOfType<pcpp::IPv6Layer>();
	PTF_ASSERT(ipv6Layer->getExtensionCount() == 4, "Multiple ext packet: Num of extensions isn't 4");
	PTF_ASSERT(ipv6Layer->getExtensionOfType<pcpp::IPv6AuthenticationHeader>() != NULL, "Multiple ext packet: Cannot find AH extension");
	PTF_ASSERT(ipv6Layer->getExtensionOfType<pcpp::IPv6AuthenticationHeader>()->getAuthHeader()->securityParametersIndex = be32toh(0x100),
			"Multiple ext packet: AH ext SPI isn't 0x100");
	PTF_ASSERT(ipv6Layer->getExtensionOfType<pcpp::IPv6DestinationHeader>() != NULL, "Multiple ext packet: Cannot find Dest extension");
	PTF_ASSERT(ipv6Layer->getExtensionOfType<pcpp::IPv6DestinationHeader>()->getFirstOption().getType() == 11,
			"Multiple ext packet: Dest ext first option type isn't 11");
	PTF_ASSERT(ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>() != NULL, "Multiple ext packet: Cannot find Hop-By-Hop extension");
	PTF_ASSERT(ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>()->getFirstOption().getType() == 5,
			"Multiple ext packet: Hop-By-Hop ext first option type isn't 5");
	PTF_ASSERT(ipv6Layer->getExtensionOfType<pcpp::IPv6RoutingHeader>() != NULL, "Multiple ext packet: Cannot find Routing extension");
	PTF_ASSERT(ipv6Layer->getExtensionOfType<pcpp::IPv6RoutingHeader>()->getRoutingHeader()->routingType == 0,
			"Multiple ext packet: Routing ext - routing type isn't 0");


	// creation of Destination extension
	pcpp::EthLayer newEthLayer(*ipv6Dest.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer(*ipv6Dest.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT(newIPv6Layer.getHeaderLen() == 48, "New IPv6 layer len with old extensions isn't 48");
	newIPv6Layer.removeAllExtensions();
	PTF_ASSERT(newIPv6Layer.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	std::vector<pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder> destExtOptions;
	destExtOptions.push_back(pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(11, (uint8_t)9));
	destExtOptions.push_back(pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(1, (uint8_t)0));
	pcpp::IPv6DestinationHeader newDestExtHeader(destExtOptions);
	newIPv6Layer.addExtension<pcpp::IPv6DestinationHeader>(newDestExtHeader);

	pcpp::UdpLayer newUdpLayer(*ipv6Dest.getLayerOfType<pcpp::UdpLayer>());
	pcpp::PayloadLayer newPayloadLayer(*ipv6Dest.getLayerOfType<pcpp::PayloadLayer>());

	pcpp::Packet newPacket;
	newPacket.addLayer(&newEthLayer);
	newPacket.addLayer(&newIPv6Layer);
	newPacket.addLayer(&newUdpLayer);
	newPacket.addLayer(&newPayloadLayer);
	newPacket.computeCalculateFields();

	PTF_ASSERT(ipv6Dest.getRawPacket()->getRawDataLen() == newPacket.getRawPacket()->getRawDataLen(), "IPv6 Dest ext: Generated packet len (%d) is different than original packet len (%d)", newPacket.getRawPacket()->getRawDataLen(), ipv6Dest.getRawPacket()->getRawDataLen());
	PTF_ASSERT(memcmp(ipv6Dest.getRawPacket()->getRawData(), newPacket.getRawPacket()->getRawData(), ipv6Dest.getRawPacket()->getRawDataLen()) == 0, "IPv6 Dest ext: Raw packet data is different than expected");


	// creation of hop-by-hop extension
	pcpp::EthLayer newEthLayer2(*ipv6HopByHop.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer2(*ipv6HopByHop.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT(newIPv6Layer2.getHeaderLen() == 48, "New IPv6 layer len with old extensions isn't 48");
	newIPv6Layer2.removeAllExtensions();
	PTF_ASSERT(newIPv6Layer2.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	std::vector<pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder> hopByHopExtOptions;
	hopByHopExtOptions.push_back(pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(5, (uint16_t)0));
	hopByHopExtOptions.push_back(pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(1, NULL, 0));
	pcpp::IPv6HopByHopHeader newHopByHopHeader(hopByHopExtOptions);
	newIPv6Layer2.addExtension<pcpp::IPv6HopByHopHeader>(newHopByHopHeader);

	pcpp::PayloadLayer newPayloadLayer2(*ipv6HopByHop.getLayerOfType<pcpp::PayloadLayer>());

	pcpp::Packet newPacket2;
	newPacket2.addLayer(&newEthLayer2);
	newPacket2.addLayer(&newIPv6Layer2);
	newPacket2.addLayer(&newPayloadLayer2);
	newPacket2.computeCalculateFields();

	PTF_ASSERT(ipv6HopByHop.getRawPacket()->getRawDataLen() == newPacket2.getRawPacket()->getRawDataLen(), "IPv6 hop-by-hop ext: Generated packet len (%d) is different than original packet len (%d)", newPacket2.getRawPacket()->getRawDataLen(), ipv6HopByHop.getRawPacket()->getRawDataLen());
	PTF_ASSERT(memcmp(ipv6HopByHop.getRawPacket()->getRawData(), newPacket2.getRawPacket()->getRawData(), ipv6HopByHop.getRawPacket()->getRawDataLen()) == 0, "IPv6 hop-by-hop ext: Raw packet data is different than expected");


	// creation of routing extension
	pcpp::EthLayer newEthLayer3(*ipv6Routing2.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer3(*ipv6Routing2.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT(newIPv6Layer3.getHeaderLen() == 64, "New IPv6 layer len with old extensions isn't 64");
	newIPv6Layer3.removeAllExtensions();
	PTF_ASSERT(newIPv6Layer3.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	uint8_t* routingAdditionalData = new uint8_t[20];
	memset(routingAdditionalData, 0, 20);
	pcpp::IPv6Address ip6Addr(std::string("2200::210:2:0:0:4"));
	ip6Addr.copyTo(routingAdditionalData + 4);
	pcpp::IPv6RoutingHeader newRoutingHeader(0, 1, routingAdditionalData, 20);
	newIPv6Layer3.addExtension<pcpp::IPv6RoutingHeader>(newRoutingHeader);
	delete [] routingAdditionalData;

	pcpp::UdpLayer newUdpLayer3(*ipv6Routing2.getLayerOfType<pcpp::UdpLayer>());

	pcpp::Packet newPacket3;
	newPacket3.addLayer(&newEthLayer3);
	newPacket3.addLayer(&newIPv6Layer3);
	newPacket3.addLayer(&newUdpLayer3);

	PTF_ASSERT(ipv6Routing2.getRawPacket()->getRawDataLen() == newPacket3.getRawPacket()->getRawDataLen(), "IPv6 routing ext: Generated packet len (%d) is different than original packet len (%d)", newPacket3.getRawPacket()->getRawDataLen(), ipv6Routing2.getRawPacket()->getRawDataLen());
	PTF_ASSERT(memcmp(ipv6Routing2.getRawPacket()->getRawData(), newPacket3.getRawPacket()->getRawData(), ipv6Routing2.getRawPacket()->getRawDataLen()) == 0, "IPv6 routing ext: Raw packet data is different than expected");


	// creation of AH extension
	pcpp::EthLayer newEthLayer4(*ipv6AuthHdr.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer4(*ipv6AuthHdr.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT(newIPv6Layer4.getHeaderLen() == 64, "New IPv6 layer len with old extensions isn't 64");
	newIPv6Layer4.removeAllExtensions();
	PTF_ASSERT(newIPv6Layer4.getHeaderLen() == 40, "New IPv6 layer len without extensions isn't 40");

	pcpp::IPv6AuthenticationHeader newAHExtension(0x100, 32, expectedICV, 12);
	newIPv6Layer4.addExtension<pcpp::IPv6AuthenticationHeader>(newAHExtension);

	pcpp::PayloadLayer newPayloadLayer4(*ipv6AuthHdr.getLayerOfType<pcpp::PayloadLayer>());

	pcpp::Packet newPacket4;
	newPacket4.addLayer(&newEthLayer4);
	newPacket4.addLayer(&newIPv6Layer4);
	newPacket4.addLayer(&newPayloadLayer4);
	newPacket4.computeCalculateFields();

	PTF_ASSERT(ipv6AuthHdr.getRawPacket()->getRawDataLen() == newPacket4.getRawPacket()->getRawDataLen(), "IPv6 AH ext: Generated packet len (%d) is different than original packet len (%d)", newPacket4.getRawPacket()->getRawDataLen(), ipv6AuthHdr.getRawPacket()->getRawDataLen());
	PTF_ASSERT(memcmp(ipv6AuthHdr.getRawPacket()->getRawData(), newPacket4.getRawPacket()->getRawData(), ipv6AuthHdr.getRawPacket()->getRawDataLen()) == 0, "IPv6 AH ext: Raw packet data is different than expected");


	// creation of packet with several extensions
	pcpp::EthLayer newEthLayer5(*ipv6AuthHdr.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer5(*ipv6AuthHdr.getLayerOfType<pcpp::IPv6Layer>());
	newIPv6Layer5.removeAllExtensions();

	newIPv6Layer5.addExtension<pcpp::IPv6HopByHopHeader>(newHopByHopHeader);
	newIPv6Layer5.addExtension<pcpp::IPv6DestinationHeader>(newDestExtHeader);
	newIPv6Layer5.addExtension<pcpp::IPv6RoutingHeader>(newRoutingHeader);
	newIPv6Layer5.addExtension<pcpp::IPv6AuthenticationHeader>(newAHExtension);

	pcpp::PayloadLayer newPayloadLayer5(*ipv6AuthHdr.getLayerOfType<pcpp::PayloadLayer>());

	pcpp::Packet newPacket5;
	newPacket5.addLayer(&newEthLayer5);
	newPacket5.addLayer(&newIPv6Layer5);
	newPacket5.addLayer(&newPayloadLayer5);
	newPacket5.computeCalculateFields();

	PTF_ASSERT(ipv6MultipleOptions.getRawPacket()->getRawDataLen() == newPacket5.getRawPacket()->getRawDataLen(), "IPv6 multiple ext: Generated packet len (%d) is different than original packet len (%d)", newPacket5.getRawPacket()->getRawDataLen(), ipv6MultipleOptions.getRawPacket()->getRawDataLen());
	PTF_ASSERT(memcmp(ipv6MultipleOptions.getRawPacket()->getRawData(), newPacket5.getRawPacket()->getRawData(), ipv6MultipleOptions.getRawPacket()->getRawDataLen()) == 0, "IPv6 multiple ext: Raw packet data is different than expected");
} // IPv6ExtensionsTest
