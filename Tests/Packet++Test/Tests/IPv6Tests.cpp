#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "IpAddress.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "IcmpV6Layer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include "SystemUtils.h"

PTF_TEST_CASE(IPv6UdpPacketParseAndCreate)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv6UdpPacket.dat");

	pcpp::Packet ip6UdpPacket(&rawPacket1);
	PTF_ASSERT_TRUE(ip6UdpPacket.isPacketOfType(pcpp::IPv6));
	PTF_ASSERT_TRUE(ip6UdpPacket.isPacketOfType(pcpp::IP));
	PTF_ASSERT_FALSE(ip6UdpPacket.isPacketOfType(pcpp::IPv4));
	PTF_ASSERT_FALSE(ip6UdpPacket.isPacketOfType(pcpp::TCP));
	pcpp::IPv6Layer* ipv6Layer = nullptr;
	ipv6Layer = ip6UdpPacket.getLayerOfType<pcpp::IPv6Layer>();
	PTF_ASSERT_NOT_NULL(ipv6Layer);
	PTF_ASSERT_EQUAL(ipv6Layer->getIPv6Header()->nextHeader, 17);
	PTF_ASSERT_EQUAL(ipv6Layer->getIPv6Header()->ipVersion, 6);
	pcpp::IPv6Address srcIP("fe80::4dc7:f593:1f7b:dc11");
	pcpp::IPv6Address dstIP("ff02::c");
	PTF_ASSERT_EQUAL(ipv6Layer->getSrcIPAddress(), srcIP);
	PTF_ASSERT_EQUAL(ipv6Layer->getDstIPAddress(), dstIP);
	pcpp::UdpLayer* pUdpLayer = nullptr;
	pUdpLayer = ip6UdpPacket.getLayerOfType<pcpp::UdpLayer>();
	PTF_ASSERT_NOT_NULL(pUdpLayer);
	PTF_ASSERT_EQUAL(pUdpLayer->getDstPort(), 1900);
	PTF_ASSERT_EQUAL(pUdpLayer->getSrcPort(), 63628);
	PTF_ASSERT_EQUAL(pUdpLayer->getUdpHeader()->length, htobe16(154));
	PTF_ASSERT_EQUAL(pUdpLayer->getUdpHeader()->headerChecksum, htobe16(0x5fea));

	pcpp::EthLayer ethLayer(pcpp::MacAddress("6c:f0:49:b2:de:6e"), pcpp::MacAddress("33:33:00:00:00:0c"));

	pcpp::IPv6Layer ip6Layer(srcIP, dstIP);
	pcpp::ip6_hdr* ip6Header = ip6Layer.getIPv6Header();
	ip6Header->hopLimit = 1;
	ip6Header->nextHeader = 17;

	pcpp::UdpLayer udpLayer(63628, 1900);

	pcpp::Layer* afterIpv6Layer = pUdpLayer->getNextLayer();
	uint8_t* payloadData = new uint8_t[afterIpv6Layer->getDataLen()];
	afterIpv6Layer->copyData(payloadData);
	pcpp::PayloadLayer payloadLayer(payloadData, afterIpv6Layer->getDataLen());

	pcpp::Packet ip6UdpPacketNew(1);
	PTF_ASSERT_TRUE(ip6UdpPacketNew.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(ip6UdpPacketNew.addLayer(&ip6Layer));
	PTF_ASSERT_TRUE(ip6UdpPacketNew.addLayer(&udpLayer));
	PTF_ASSERT_TRUE(ip6UdpPacketNew.addLayer(&payloadLayer));
	ip6UdpPacketNew.computeCalculateFields();

	PTF_ASSERT_EQUAL(ip6UdpPacketNew.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(ip6UdpPacketNew.getRawPacket()->getRawData(), buffer1, bufferLength1);

	pcpp::IPv6Layer ipv6LayerEmpty;
	ipv6LayerEmpty.setSrcIPv6Address(srcIP);
	PTF_ASSERT_EQUAL(ipv6LayerEmpty.getSrcIPv6Address(), srcIP);

	ipv6LayerEmpty.setDstIPv6Address(dstIP);
	PTF_ASSERT_EQUAL(ipv6LayerEmpty.getDstIPv6Address(), dstIP);

	delete[] payloadData;
}  // IPv6UdpPacketParseAndCreate

PTF_TEST_CASE(IPv6FragmentationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

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
	PTF_ASSERT_EQUAL(fragHeader->getExtensionType(), pcpp::IPv6Extension::IPv6Fragmentation, enum);
	PTF_ASSERT_NOT_NULL(fragHeader);
	PTF_ASSERT_TRUE(fragHeader->isFirstFragment());
	PTF_ASSERT_FALSE(fragHeader->isLastFragment());
	PTF_ASSERT_EQUAL(fragHeader->getFragmentOffset(), 0);
	PTF_ASSERT_EQUAL(be32toh(fragHeader->getFragHeader()->id), 0xf88eb466);
	PTF_ASSERT_EQUAL(fragHeader->getFragHeader()->nextHeader, pcpp::PACKETPP_IPPROTO_UDP);

	ipv6Layer = frag2.getLayerOfType<pcpp::IPv6Layer>();
	fragHeader = ipv6Layer->getExtensionOfType<pcpp::IPv6FragmentationHeader>();
	PTF_ASSERT_EQUAL(fragHeader->getExtensionType(), pcpp::IPv6Extension::IPv6Fragmentation, enum);
	PTF_ASSERT_NOT_NULL(fragHeader);
	PTF_ASSERT_FALSE(fragHeader->isFirstFragment());
	PTF_ASSERT_FALSE(fragHeader->isLastFragment());
	PTF_ASSERT_EQUAL(fragHeader->getFragmentOffset(), 1448);
	PTF_ASSERT_EQUAL(be32toh(fragHeader->getFragHeader()->id), 0xf88eb466);
	PTF_ASSERT_EQUAL(fragHeader->getFragHeader()->nextHeader, pcpp::PACKETPP_IPPROTO_UDP);

	ipv6Layer = frag3.getLayerOfType<pcpp::IPv6Layer>();
	fragHeader = ipv6Layer->getExtensionOfType<pcpp::IPv6FragmentationHeader>();
	PTF_ASSERT_EQUAL(fragHeader->getExtensionType(), pcpp::IPv6Extension::IPv6Fragmentation, enum);
	PTF_ASSERT_NOT_NULL(fragHeader);
	PTF_ASSERT_FALSE(fragHeader->isFirstFragment());
	PTF_ASSERT_FALSE(fragHeader->isLastFragment());
	PTF_ASSERT_EQUAL(fragHeader->getFragmentOffset(), 2896);
	PTF_ASSERT_EQUAL(be32toh(fragHeader->getFragHeader()->id), 0xf88eb466);
	PTF_ASSERT_EQUAL(fragHeader->getFragHeader()->nextHeader, pcpp::PACKETPP_IPPROTO_UDP);

	ipv6Layer = frag4.getLayerOfType<pcpp::IPv6Layer>();
	PTF_ASSERT_EQUAL(ipv6Layer->getHeaderLen(), 48);
	fragHeader = ipv6Layer->getExtensionOfType<pcpp::IPv6FragmentationHeader>();
	PTF_ASSERT_EQUAL(fragHeader->getExtensionType(), pcpp::IPv6Extension::IPv6Fragmentation, enum);
	PTF_ASSERT_NOT_NULL(fragHeader);
	PTF_ASSERT_FALSE(fragHeader->isFirstFragment());
	PTF_ASSERT_TRUE(fragHeader->isLastFragment());
	PTF_ASSERT_EQUAL(fragHeader->getFragmentOffset(), 4344);
	PTF_ASSERT_EQUAL(be32toh(fragHeader->getFragHeader()->id), 0xf88eb466);
	PTF_ASSERT_EQUAL(fragHeader->getFragHeader()->nextHeader, pcpp::PACKETPP_IPPROTO_UDP);

	pcpp::EthLayer newEthLayer(*frag1.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer(*frag1.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT_EQUAL(newIPv6Layer.getHeaderLen(), 48);
	newIPv6Layer.removeAllExtensions();
	PTF_ASSERT_EQUAL(newIPv6Layer.getHeaderLen(), 40);

	pcpp::PayloadLayer newPayloadLayer(*frag4.getLayerOfType<pcpp::PayloadLayer>());

	pcpp::Packet newFrag;
	newFrag.addLayer(&newEthLayer);
	newFrag.addLayer(&newIPv6Layer);
	newFrag.addLayer(&newPayloadLayer);

	pcpp::IPv6FragmentationHeader newFragHeader(0xf88eb466, 4344, true);
	newIPv6Layer.addExtension<pcpp::IPv6FragmentationHeader>(newFragHeader);
	PTF_ASSERT_EQUAL(newIPv6Layer.getHeaderLen(), 48);

	newFrag.computeCalculateFields();

	PTF_ASSERT_EQUAL(frag4.getRawPacket()->getRawDataLen(), newFrag.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(frag4.getRawPacket()->getRawData(), newFrag.getRawPacket()->getRawData(),
	                       frag4.getRawPacket()->getRawDataLen());
}  // IPv6FragmentationTest

PTF_TEST_CASE(IPv6ExtensionsTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

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

	// parsing of Destination extension
	pcpp::IPv6Layer* ipv6Layer = ipv6Dest.getLayerOfType<pcpp::IPv6Layer>();
	PTF_ASSERT_EQUAL(ipv6Layer->getExtensionCount(), 1);
	pcpp::IPv6HopByHopHeader* hopByHopExt = ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>();
	pcpp::IPv6DestinationHeader* destExt = ipv6Layer->getExtensionOfType<pcpp::IPv6DestinationHeader>();
	PTF_ASSERT_NULL(hopByHopExt);
	PTF_ASSERT_NOT_NULL(destExt);
	PTF_ASSERT_EQUAL(destExt->getExtensionType(), pcpp::IPv6Extension::IPv6Destination, enum);
	PTF_ASSERT_EQUAL(destExt->getOptionCount(), 2);
	pcpp::IPv6TLVOptionHeader::IPv6Option option = destExt->getFirstOption();
	PTF_ASSERT_FALSE(option.isNull());
	PTF_ASSERT_EQUAL(option.getType(), 11);
	PTF_ASSERT_EQUAL(option.getTotalSize(), 3);
	PTF_ASSERT_EQUAL(option.getDataSize(), 1);
	PTF_ASSERT_EQUAL(option.getValueAs<uint8_t>(), 9);
	option = destExt->getNextOption(option);
	PTF_ASSERT_FALSE(option.isNull());
	PTF_ASSERT_EQUAL(option.getType(), 1);
	PTF_ASSERT_EQUAL(option.getTotalSize(), 3);
	PTF_ASSERT_EQUAL(option.getDataSize(), 1);
	PTF_ASSERT_EQUAL(option.getValueAs<uint8_t>(), 0);
	option = destExt->getNextOption(option);
	PTF_ASSERT_TRUE(option.isNull());
	option = destExt->getOption(11);
	PTF_ASSERT_FALSE(option.isNull());
	PTF_ASSERT_EQUAL(option.getTotalSize(), 3);
	PTF_ASSERT_TRUE(destExt->getOption(12).isNull());
	PTF_ASSERT_TRUE(destExt->getOption(0).isNull());

	// parsing of Hop-By-Hop extension
	ipv6Layer = ipv6HopByHop.getLayerOfType<pcpp::IPv6Layer>();
	hopByHopExt = ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>();
	destExt = ipv6Layer->getExtensionOfType<pcpp::IPv6DestinationHeader>();
	PTF_ASSERT_NULL(destExt);
	PTF_ASSERT_NOT_NULL(hopByHopExt);
	PTF_ASSERT_EQUAL(hopByHopExt->getExtensionType(), pcpp::IPv6Extension::IPv6HopByHop, enum);
	PTF_ASSERT_EQUAL(hopByHopExt->getOptionCount(), 2);
	PTF_ASSERT_TRUE(hopByHopExt->getOption(3).isNull());
	PTF_ASSERT_TRUE(hopByHopExt->getOption(0).isNull());
	option = hopByHopExt->getFirstOption();
	PTF_ASSERT_EQUAL(option.getType(), 5);
	PTF_ASSERT_EQUAL(option.getTotalSize(), 4);
	PTF_ASSERT_EQUAL(option.getDataSize(), 2);
	PTF_ASSERT_EQUAL(option.getValueAs<uint16_t>(), 0);
	option = hopByHopExt->getNextOption(option);
	PTF_ASSERT_FALSE(option.isNull());
	PTF_ASSERT_EQUAL(option.getType(), 1);
	PTF_ASSERT_EQUAL(option.getTotalSize(), 2);
	PTF_ASSERT_EQUAL(option.getDataSize(), 0);
	PTF_ASSERT_EQUAL(option.getValueAs<uint8_t>(), 0);
	option = hopByHopExt->getNextOption(option);
	PTF_ASSERT_TRUE(option.isNull());

	// parsing of routing extension #1
	ipv6Layer = ipv6Routing1.getLayerOfType<pcpp::IPv6Layer>();
	hopByHopExt = ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>();
	PTF_ASSERT_EQUAL(ipv6Layer->getExtensionCount(), 1);
	pcpp::IPv6RoutingHeader* routingExt = ipv6Layer->getExtensionOfType<pcpp::IPv6RoutingHeader>();
	PTF_ASSERT_NULL(destExt);
	PTF_ASSERT_NOT_NULL(routingExt);
	PTF_ASSERT_EQUAL(routingExt->getExtensionType(), pcpp::IPv6Extension::IPv6Routing, enum);
	PTF_ASSERT_EQUAL(routingExt->getRoutingHeader()->routingType, 0);
	PTF_ASSERT_EQUAL(routingExt->getRoutingHeader()->segmentsLeft, 2);
	PTF_ASSERT_EQUAL(routingExt->getRoutingAdditionalDataLength(), 36);
	PTF_ASSERT_EQUAL(routingExt->getRoutingAdditionalDataAsIPv6Address(4), pcpp::IPv6Address("2200::210:2:0:0:4"));
	PTF_ASSERT_EQUAL(routingExt->getRoutingAdditionalDataAsIPv6Address(20), pcpp::IPv6Address("2200::240:2:0:0:4"));

	// parsing of routing extension #2
	ipv6Layer = ipv6Routing2.getLayerOfType<pcpp::IPv6Layer>();
	routingExt = ipv6Layer->getExtensionOfType<pcpp::IPv6RoutingHeader>();
	PTF_ASSERT_NOT_NULL(routingExt);
	PTF_ASSERT_EQUAL(routingExt->getExtensionType(), pcpp::IPv6Extension::IPv6Routing, enum);
	PTF_ASSERT_EQUAL(routingExt->getRoutingHeader()->routingType, 0);
	PTF_ASSERT_EQUAL(routingExt->getRoutingHeader()->segmentsLeft, 1);
	PTF_ASSERT_EQUAL(routingExt->getRoutingAdditionalDataLength(), 20);
	PTF_ASSERT_EQUAL(routingExt->getRoutingAdditionalDataAsIPv6Address(4), pcpp::IPv6Address("2200::210:2:0:0:4"));
	PTF_ASSERT_EQUAL(routingExt->getRoutingAdditionalDataAsIPv6Address(20), pcpp::IPv6Address::Zero);

	// parsing of authentication header extension
	ipv6Layer = ipv6AuthHdr.getLayerOfType<pcpp::IPv6Layer>();
	pcpp::IPv6AuthenticationHeader* authHdrExt = ipv6Layer->getExtensionOfType<pcpp::IPv6AuthenticationHeader>();
	PTF_ASSERT_NOT_NULL(authHdrExt);
	PTF_ASSERT_EQUAL(authHdrExt->getExtensionType(), pcpp::IPv6Extension::IPv6AuthenticationHdr, enum);
	PTF_ASSERT_EQUAL(authHdrExt->getAuthHeader()->securityParametersIndex, htobe32(0x100));
	PTF_ASSERT_EQUAL(authHdrExt->getAuthHeader()->sequenceNumber, htobe32(32));
	PTF_ASSERT_EQUAL(authHdrExt->getIntegrityCheckValueLength(), 12);
	uint8_t expectedICV[12] = { 0x35, 0x48, 0x21, 0x48, 0xb2, 0x43, 0x5a, 0x23, 0xdc, 0xdd, 0x55, 0x36 };
	PTF_ASSERT_BUF_COMPARE(expectedICV, authHdrExt->getIntegrityCheckValue(),
	                       authHdrExt->getIntegrityCheckValueLength());

	// parsing of multiple options in one IPv6 layer
	ipv6Layer = ipv6MultipleOptions.getLayerOfType<pcpp::IPv6Layer>();
	PTF_ASSERT_EQUAL(ipv6Layer->getExtensionCount(), 4);
	PTF_ASSERT_NOT_NULL(ipv6Layer->getExtensionOfType<pcpp::IPv6AuthenticationHeader>());
	PTF_ASSERT_EQUAL(
	    ipv6Layer->getExtensionOfType<pcpp::IPv6AuthenticationHeader>()->getAuthHeader()->securityParametersIndex,
	    be32toh(0x100));
	PTF_ASSERT_NOT_NULL(ipv6Layer->getExtensionOfType<pcpp::IPv6DestinationHeader>());
	PTF_ASSERT_EQUAL(ipv6Layer->getExtensionOfType<pcpp::IPv6DestinationHeader>()->getFirstOption().getType(), 11);
	PTF_ASSERT_NOT_NULL(ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>());
	PTF_ASSERT_EQUAL(ipv6Layer->getExtensionOfType<pcpp::IPv6HopByHopHeader>()->getFirstOption().getType(), 5);
	PTF_ASSERT_NOT_NULL(ipv6Layer->getExtensionOfType<pcpp::IPv6RoutingHeader>());
	PTF_ASSERT_EQUAL(ipv6Layer->getExtensionOfType<pcpp::IPv6RoutingHeader>()->getRoutingHeader()->routingType, 0);

	// creation of Destination extension
	pcpp::EthLayer newEthLayer(*ipv6Dest.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer(*ipv6Dest.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT_EQUAL(newIPv6Layer.getHeaderLen(), 48);
	newIPv6Layer.removeAllExtensions();
	PTF_ASSERT_EQUAL(newIPv6Layer.getHeaderLen(), 40);

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

	PTF_ASSERT_EQUAL(ipv6Dest.getRawPacket()->getRawDataLen(), newPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(ipv6Dest.getRawPacket()->getRawData(), newPacket.getRawPacket()->getRawData(),
	                       ipv6Dest.getRawPacket()->getRawDataLen());

	// creation of hop-by-hop extension
	pcpp::EthLayer newEthLayer2(*ipv6HopByHop.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer2(*ipv6HopByHop.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT_EQUAL(newIPv6Layer2.getHeaderLen(), 48);
	newIPv6Layer2.removeAllExtensions();
	PTF_ASSERT_EQUAL(newIPv6Layer2.getHeaderLen(), 40);

	std::vector<pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder> hopByHopExtOptions;
	hopByHopExtOptions.push_back(pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(5, (uint16_t)0));
	hopByHopExtOptions.push_back(pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(1, nullptr, 0));
	pcpp::IPv6HopByHopHeader newHopByHopHeader(hopByHopExtOptions);
	newIPv6Layer2.addExtension<pcpp::IPv6HopByHopHeader>(newHopByHopHeader);

	pcpp::IcmpV6Layer newIcmpV6Layer2(*ipv6HopByHop.getLayerOfType<pcpp::IcmpV6Layer>());

	pcpp::Packet newPacket2;
	newPacket2.addLayer(&newEthLayer2);
	newPacket2.addLayer(&newIPv6Layer2);
	newPacket2.addLayer(&newIcmpV6Layer2);
	newPacket2.computeCalculateFields();

	PTF_ASSERT_EQUAL(ipv6HopByHop.getRawPacket()->getRawDataLen(), newPacket2.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(ipv6HopByHop.getRawPacket()->getRawData(), newPacket2.getRawPacket()->getRawData(),
	                       ipv6HopByHop.getRawPacket()->getRawDataLen());

	// creation of routing extension
	pcpp::EthLayer newEthLayer3(*ipv6Routing2.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer3(*ipv6Routing2.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT_EQUAL(newIPv6Layer3.getHeaderLen(), 64);
	newIPv6Layer3.removeAllExtensions();
	PTF_ASSERT_EQUAL(newIPv6Layer3.getHeaderLen(), 40);

	uint8_t* routingAdditionalData = new uint8_t[20];
	memset(routingAdditionalData, 0, 20);
	pcpp::IPv6Address ip6Addr("2200::210:2:0:0:4");
	ip6Addr.copyTo(routingAdditionalData + 4);
	pcpp::IPv6RoutingHeader newRoutingHeader(0, 1, routingAdditionalData, 20);
	newIPv6Layer3.addExtension<pcpp::IPv6RoutingHeader>(newRoutingHeader);
	delete[] routingAdditionalData;

	pcpp::UdpLayer newUdpLayer3(*ipv6Routing2.getLayerOfType<pcpp::UdpLayer>());

	pcpp::Packet newPacket3;
	newPacket3.addLayer(&newEthLayer3);
	newPacket3.addLayer(&newIPv6Layer3);
	newPacket3.addLayer(&newUdpLayer3);

	PTF_ASSERT_EQUAL(ipv6Routing2.getRawPacket()->getRawDataLen(), newPacket3.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(ipv6Routing2.getRawPacket()->getRawData(), newPacket3.getRawPacket()->getRawData(),
	                       ipv6Routing2.getRawPacket()->getRawDataLen());

	// creation of AH extension
	pcpp::EthLayer newEthLayer4(*ipv6AuthHdr.getLayerOfType<pcpp::EthLayer>());

	pcpp::IPv6Layer newIPv6Layer4(*ipv6AuthHdr.getLayerOfType<pcpp::IPv6Layer>());
	PTF_ASSERT_EQUAL(newIPv6Layer4.getHeaderLen(), 64);
	newIPv6Layer4.removeAllExtensions();
	PTF_ASSERT_EQUAL(newIPv6Layer4.getHeaderLen(), 40);

	pcpp::IPv6AuthenticationHeader newAHExtension(0x100, 32, expectedICV, 12);
	newIPv6Layer4.addExtension<pcpp::IPv6AuthenticationHeader>(newAHExtension);

	pcpp::PayloadLayer newPayloadLayer4(*ipv6AuthHdr.getLayerOfType<pcpp::PayloadLayer>());

	pcpp::Packet newPacket4;
	newPacket4.addLayer(&newEthLayer4);
	newPacket4.addLayer(&newIPv6Layer4);
	newPacket4.addLayer(&newPayloadLayer4);
	newPacket4.computeCalculateFields();

	PTF_ASSERT_EQUAL(ipv6AuthHdr.getRawPacket()->getRawDataLen(), newPacket4.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(ipv6AuthHdr.getRawPacket()->getRawData(), newPacket4.getRawPacket()->getRawData(),
	                       ipv6AuthHdr.getRawPacket()->getRawDataLen());

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

	PTF_ASSERT_EQUAL(ipv6MultipleOptions.getRawPacket()->getRawDataLen(), newPacket5.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(ipv6MultipleOptions.getRawPacket()->getRawData(), newPacket5.getRawPacket()->getRawData(),
	                       ipv6MultipleOptions.getRawPacket()->getRawDataLen());
}  // IPv6ExtensionsTest
