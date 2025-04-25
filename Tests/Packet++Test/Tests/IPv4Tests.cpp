#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include <sstream>
#include "EndianPortable.h"
#include "Logger.h"
#include "MacAddress.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(IPv4PacketCreation)
{
	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

	pcpp::IPv4Address ipSrc("1.1.1.1");
	pcpp::IPv4Address ipDst("20.20.20.20");
	pcpp::IPv4Layer ip4Layer(ipSrc, ipDst);
	ip4Layer.getIPv4Header()->protocol = pcpp::PACKETPP_IPPROTO_TCP;

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa };
	pcpp::PayloadLayer payloadLayer(payload, 10);

	pcpp::Packet ip4Packet(1);
	PTF_ASSERT_TRUE(ip4Packet.addLayer(&ethLayer));

	pcpp::Packet tmpPacket(50);
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(tmpPacket.addLayer(&ethLayer));
	pcpp::Logger::getInstance().enableLogs();

	pcpp::RawPacket* rawPacket = ip4Packet.getRawPacket();
	PTF_ASSERT_NOT_NULL(rawPacket);
	PTF_ASSERT_EQUAL(rawPacket->getRawDataLen(), 14);

	PTF_ASSERT_TRUE(ip4Packet.addLayer(&ip4Layer));
	PTF_ASSERT_TRUE(ip4Packet.addLayer(&payloadLayer));

	ip4Packet.computeCalculateFields();

	PTF_ASSERT_EQUAL(ip4Packet.getLayerOfType<pcpp::EthLayer>()->getDataLen(), 44);
	PTF_ASSERT_NOT_NULL(ip4Packet.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::iphdr* ipHeader = ip4Layer.getIPv4Header();
	PTF_ASSERT_EQUAL(ip4Layer.getSrcIPAddress(), ipSrc);
	PTF_ASSERT_EQUAL(ip4Layer.getDstIPAddress(), ipDst);
	PTF_ASSERT_EQUAL(ipHeader->ipVersion, 4);
	PTF_ASSERT_EQUAL(ipHeader->internetHeaderLength, 5);
	PTF_ASSERT_EQUAL(ipHeader->totalLength, htobe16(30));
	PTF_ASSERT_EQUAL(ipHeader->protocol, (uint8_t)pcpp::PACKETPP_IPPROTO_TCP);
	PTF_ASSERT_EQUAL(ipHeader->headerChecksum, htobe16(0x90b1));
}  // Ipv4PacketCreation

PTF_TEST_CASE(IPv4PacketParsing)
{
	timeval time;
	gettimeofday(&time, nullptr);

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IcmpPacket.dat");

		pcpp::Packet ip4Packet(&rawPacket1);
		PTF_ASSERT_TRUE(ip4Packet.isPacketOfType(pcpp::Ethernet));
		PTF_ASSERT_NOT_NULL(ip4Packet.getLayerOfType<pcpp::EthLayer>());
		PTF_ASSERT_TRUE(ip4Packet.isPacketOfType(pcpp::IP));
		PTF_ASSERT_TRUE(ip4Packet.isPacketOfType(pcpp::IPv4));
		PTF_ASSERT_NOT_NULL(ip4Packet.getLayerOfType<pcpp::IPv4Layer>());

		pcpp::EthLayer* ethLayer = ip4Packet.getLayerOfType<pcpp::EthLayer>();
		PTF_ASSERT_EQUAL(be16toh(ethLayer->getEthHeader()->etherType), PCPP_ETHERTYPE_IP);

		pcpp::IPv4Layer* ipv4Layer = ip4Packet.getLayerOfType<pcpp::IPv4Layer>();
		pcpp::IPv4Address ip4addr1("10.0.0.4");
		pcpp::IPv4Address ip4addr2("1.1.1.1");
		PTF_ASSERT_EQUAL(ipv4Layer->getIPv4Header()->protocol, 1);
		PTF_ASSERT_EQUAL(ipv4Layer->getIPv4Header()->ipVersion, 4);
		PTF_ASSERT_EQUAL(ipv4Layer->getIPv4Header()->ipSrc, ip4addr1.toInt());
		PTF_ASSERT_EQUAL(ipv4Layer->getIPv4Header()->ipDst, ip4addr2.toInt());
		PTF_ASSERT_TRUE(ipv4Layer->getFirstOption().isNull());
		PTF_ASSERT_TRUE(ipv4Layer->getOption(pcpp::IPV4OPT_CommercialSecurity).isNull());
		PTF_ASSERT_EQUAL(ipv4Layer->getOptionCount(), 0);
	}

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv4-TSO.dat");

		pcpp::Packet ip4TSO(&rawPacket1);

		auto ipv4Layer = ip4TSO.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_NOT_NULL(ipv4Layer);
		PTF_ASSERT_EQUAL(ipv4Layer->getHeaderLen(), 20);
		PTF_ASSERT_EQUAL(ipv4Layer->getIPv4Header()->totalLength, 0);
		PTF_ASSERT_EQUAL(ipv4Layer->getDataLen(), 60);
		PTF_ASSERT_NOT_NULL(ipv4Layer->getNextLayer());
		PTF_ASSERT_EQUAL(ipv4Layer->getNextLayer()->getProtocol(), pcpp::ICMP, enum);
	}

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ipv4-malformed1.dat");

		pcpp::Packet bogusPkt(&rawPacket1, pcpp::IPv4);

		auto ipv4Layer = bogusPkt.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_NULL(ipv4Layer);
	}

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ipv4-malformed2.dat");

		pcpp::Packet bogusPkt(&rawPacket1, pcpp::IPv4);

		auto ipv4Layer = bogusPkt.getLayerOfType<pcpp::IPv4Layer>();
		PTF_ASSERT_EQUAL(htobe16(ipv4Layer->getIPv4Header()->totalLength), 11);
		PTF_ASSERT_EQUAL(ipv4Layer->getLayerPayloadSize(), 0);
	}

	{
		READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv4-encapsulated-IPv6.dat");
		pcpp::Packet encapsulatedPkt(&rawPacket1, pcpp::IPv6);

		pcpp::IPv6Layer* ipv6Layer = encapsulatedPkt.getLayerOfType<pcpp::IPv6Layer>();
		PTF_ASSERT_NOT_NULL(ipv6Layer);
	}
}  // Ipv4PacketParsing

PTF_TEST_CASE(IPv4FragmentationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv4Frag1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IPv4Frag2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/IPv4Frag3.dat");

	pcpp::Packet frag1(&rawPacket1);
	pcpp::Packet frag2(&rawPacket2);
	pcpp::Packet frag3(&rawPacket3);

	pcpp::IPv4Layer* ipLayer = frag1.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_TRUE(ipLayer->isFragment());
	PTF_ASSERT_TRUE(ipLayer->isFirstFragment());
	PTF_ASSERT_FALSE(ipLayer->isLastFragment());
	PTF_ASSERT_EQUAL(ipLayer->getFragmentOffset(), 0);
	PTF_ASSERT_NOT_EQUAL((ipLayer->getFragmentFlags() & PCPP_IP_MORE_FRAGMENTS), 0);
	PTF_ASSERT_NOT_NULL(ipLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ipLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);

	ipLayer = frag2.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_TRUE(ipLayer->isFragment());
	PTF_ASSERT_FALSE(ipLayer->isFirstFragment());
	PTF_ASSERT_FALSE(ipLayer->isLastFragment());
	PTF_ASSERT_EQUAL(ipLayer->getFragmentOffset(), 1480);
	PTF_ASSERT_NOT_EQUAL((ipLayer->getFragmentFlags() & PCPP_IP_MORE_FRAGMENTS), 0);
	PTF_ASSERT_NOT_NULL(ipLayer->getNextLayer());
	PTF_ASSERT_EQUAL(ipLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);

	ipLayer = frag3.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_TRUE(ipLayer->isFragment());
	PTF_ASSERT_FALSE(ipLayer->isFirstFragment());
	PTF_ASSERT_TRUE(ipLayer->isLastFragment());
	PTF_ASSERT_EQUAL(ipLayer->getFragmentOffset(), 2960);
	PTF_ASSERT_EQUAL(ipLayer->getFragmentFlags(), 0);
	PTF_ASSERT_NOT_NULL(ipLayer->getNextLayer())
	PTF_ASSERT_EQUAL(ipLayer->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);
}  // Ipv4FragmentationTest

PTF_TEST_CASE(IPv4OptionsParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv4Option1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IPv4Option2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/IPv4Option3.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/IPv4Option4.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/IPv4Option5.dat");
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/IPv4Option6.dat");
	READ_FILE_AND_CREATE_PACKET(7, "PacketExamples/IPv4Option7.dat");

	pcpp::Packet ipOpt1(&rawPacket1);
	pcpp::Packet ipOpt2(&rawPacket2);
	pcpp::Packet ipOpt3(&rawPacket3);
	pcpp::Packet ipOpt4(&rawPacket4);
	pcpp::Packet ipOpt5(&rawPacket5);
	pcpp::Packet ipOpt6(&rawPacket6);
	pcpp::Packet ipOpt7(&rawPacket7);

	pcpp::IPv4Layer* ipLayer = ipOpt1.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_EQUAL(ipLayer->getHeaderLen(), 44);
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 3);
	pcpp::IPv4Option opt = ipLayer->getFirstOption();
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_CommercialSecurity, enum);
	PTF_ASSERT_EQUAL(opt.getDataSize(), 20);
	PTF_ASSERT_EQUAL(opt.getTotalSize(), 22);
	PTF_ASSERT_EQUAL(opt.getValueAs<uint32_t>(), htobe32(2));
	PTF_ASSERT_EQUAL(opt.getValueAs<uint8_t>(4), 2);
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_EndOfOptionsList, enum);
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_EndOfOptionsList, enum);
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_TRUE(opt.isNull());
	opt = ipLayer->getOption(pcpp::IPV4OPT_EndOfOptionsList);
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_EndOfOptionsList, enum);
	PTF_ASSERT_TRUE(ipLayer->getOption(pcpp::IPV4OPT_Timestamp).isNull());

	ipLayer = ipOpt2.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_EQUAL(ipLayer->getHeaderLen(), 60);
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 1);
	opt = ipLayer->getFirstOption();
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_Timestamp, enum);
	PTF_ASSERT_EQUAL(opt.getDataSize(), 38);
	PTF_ASSERT_EQUAL(opt.getTotalSize(), 40);
	pcpp::IPv4TimestampOptionValue tsValue = opt.getTimestampOptionValue();
	PTF_ASSERT_EQUAL(tsValue.type, pcpp::IPv4TimestampOptionValue::TimestampOnly, enum);
	PTF_ASSERT_EQUAL(tsValue.timestamps.size(), 1);
	PTF_ASSERT_EQUAL(tsValue.ipAddresses.size(), 0);
	PTF_ASSERT_EQUAL(tsValue.timestamps.at(0), htobe32(82524601));
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_TRUE(opt.isNull());

	ipLayer = ipOpt3.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_EQUAL(ipLayer->getHeaderLen(), 24);
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 1);
	opt = ipLayer->getFirstOption();
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_RouterAlert, enum);
	PTF_ASSERT_EQUAL(opt.getDataSize(), 2);
	PTF_ASSERT_EQUAL(opt.getTotalSize(), 4);
	PTF_ASSERT_EQUAL(opt.getValueAs<uint16_t>(), 0);
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_TRUE(opt.isNull());

	ipLayer = ipOpt4.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_EQUAL(ipLayer->getHeaderLen(), 60);
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 2);
	opt = ipLayer->getFirstOption();
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_RecordRoute, enum);
	PTF_ASSERT_EQUAL(opt.getDataSize(), 37);
	PTF_ASSERT_EQUAL(opt.getTotalSize(), 39);
	std::vector<pcpp::IPv4Address> ipAddrs = opt.getValueAsIpList();
	PTF_ASSERT_EQUAL(ipAddrs.size(), 3);
	PTF_ASSERT_EQUAL(ipAddrs.at(0), pcpp::IPv4Address("1.2.3.4"));
	PTF_ASSERT_EQUAL(ipAddrs.at(1), pcpp::IPv4Address("10.0.0.138"));
	PTF_ASSERT_EQUAL(ipAddrs.at(2), pcpp::IPv4Address("10.0.0.138"));
	pcpp::IPv4Option opt2 = ipLayer->getOption(pcpp::IPV4OPT_RecordRoute);
	PTF_ASSERT_FALSE(opt2.isNull());
	PTF_ASSERT_TRUE(opt2 == opt);

	ipLayer = ipOpt5.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_EQUAL(ipLayer->getHeaderLen(), 56);
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 1);
	opt = ipLayer->getFirstOption();
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_Timestamp, enum);
	PTF_ASSERT_EQUAL(opt.getDataSize(), 34);
	PTF_ASSERT_EQUAL(opt.getTotalSize(), 36);
	tsValue = opt.getTimestampOptionValue();
	PTF_ASSERT_EQUAL(tsValue.type, pcpp::IPv4TimestampOptionValue::TimestampAndIP, enum);
	PTF_ASSERT_EQUAL(tsValue.timestamps.size(), 3);
	PTF_ASSERT_EQUAL(tsValue.ipAddresses.size(), 3);
	PTF_ASSERT_EQUAL(tsValue.timestamps.at(0), htobe32(70037668));
	PTF_ASSERT_EQUAL(tsValue.timestamps.at(2), htobe32(77233718));
	PTF_ASSERT_EQUAL(tsValue.ipAddresses.at(0), pcpp::IPv4Address("10.0.0.6"));
	PTF_ASSERT_EQUAL(tsValue.ipAddresses.at(1), pcpp::IPv4Address("10.0.0.138"));
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_TRUE(opt.isNull());

	ipLayer = ipOpt6.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_EQUAL(ipLayer->getHeaderLen(), 28);
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 2);
	opt = ipLayer->getFirstOption();
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_NOP, enum);
	PTF_ASSERT_EQUAL(opt.getDataSize(), 0);
	PTF_ASSERT_EQUAL(opt.getTotalSize(), 1);
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_StrictSourceRoute, enum);
	PTF_ASSERT_EQUAL(opt.getDataSize(), 5);
	PTF_ASSERT_EQUAL(opt.getTotalSize(), 7);
	ipAddrs = opt.getValueAsIpList();
	PTF_ASSERT_EQUAL(ipAddrs.size(), 0);
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_TRUE(opt.isNull());

	ipLayer = ipOpt7.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_NOT_NULL(ipLayer);
	PTF_ASSERT_EQUAL(ipLayer->getHeaderLen(), 28);
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 2);
	opt = ipLayer->getFirstOption();
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_NOP, enum);
	PTF_ASSERT_EQUAL(opt.getDataSize(), 0);
	PTF_ASSERT_EQUAL(opt.getTotalSize(), 1);
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_FALSE(opt.isNull());
	PTF_ASSERT_EQUAL(opt.getIPv4OptionType(), pcpp::IPV4OPT_LooseSourceRoute, enum);
	PTF_ASSERT_EQUAL(opt.getDataSize(), 5);
	PTF_ASSERT_EQUAL(opt.getTotalSize(), 7);
	ipAddrs = opt.getValueAsIpList();
	PTF_ASSERT_EQUAL(ipAddrs.size(), 0);
	opt2 = ipLayer->getOption(pcpp::IPV4OPT_LooseSourceRoute);
	PTF_ASSERT_FALSE(opt2.isNull());
	PTF_ASSERT_TRUE(opt2 == opt);
	opt = ipLayer->getNextOption(opt);
	PTF_ASSERT_TRUE(opt.isNull());
}  // Ipv4OptionsParsingTest

PTF_TEST_CASE(IPv4OptionsEditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/IPv4-NoOptions1.dat");
	READ_FILE_INTO_BUFFER(11, "PacketExamples/IPv4Option1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/IPv4-NoOptions2.dat");
	READ_FILE_INTO_BUFFER(22, "PacketExamples/IPv4Option2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/IPv4-NoOptions3.dat");
	READ_FILE_INTO_BUFFER(33, "PacketExamples/IPv4Option3.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/IPv4-NoOptions4.dat");
	READ_FILE_INTO_BUFFER(44, "PacketExamples/IPv4Option4.dat");
	READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/IPv4-NoOptions5.dat");
	READ_FILE_INTO_BUFFER(55, "PacketExamples/IPv4Option5.dat");
	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/IPv4-NoOptions6.dat");
	READ_FILE_INTO_BUFFER(66, "PacketExamples/IPv4Option6.dat");
	READ_FILE_AND_CREATE_PACKET(7, "PacketExamples/IPv4-NoOptions7.dat");
	READ_FILE_INTO_BUFFER(77, "PacketExamples/IPv4Option7.dat");

	pcpp::Packet ipOpt1(&rawPacket1);
	pcpp::Packet ipOpt2(&rawPacket2);
	pcpp::Packet ipOpt3(&rawPacket3);
	pcpp::Packet ipOpt4(&rawPacket4);
	pcpp::Packet ipOpt5(&rawPacket5);
	pcpp::Packet ipOpt6(&rawPacket6);
	pcpp::Packet ipOpt7(&rawPacket7);

	pcpp::IPv4Layer* ipLayer = ipOpt1.getLayerOfType<pcpp::IPv4Layer>();
	uint8_t commSecOptionData[] = { 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x00, 0x02, 0x00, 0x00,
		                            0x00, 0x02, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0xef };
	PTF_ASSERT_FALSE(
	    ipLayer->addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_CommercialSecurity, commSecOptionData, 20)).isNull());
	PTF_ASSERT_FALSE(ipLayer->addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_EndOfOptionsList, nullptr, 0)).isNull());
	// clang-format off
	PTF_ASSERT_FALSE(ipLayer->addOptionAfter(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_EndOfOptionsList, nullptr, 0), pcpp::IPV4OPT_CommercialSecurity).isNull());
	// clang-format on
	ipOpt1.computeCalculateFields();

	PTF_ASSERT_EQUAL(ipOpt1.getRawPacket()->getRawDataLen(), bufferLength11);
	PTF_ASSERT_BUF_COMPARE(ipOpt1.getRawPacket()->getRawData(), buffer11, ipOpt1.getRawPacket()->getRawDataLen());

	ipLayer = ipOpt2.getLayerOfType<pcpp::IPv4Layer>();
	pcpp::IPv4TimestampOptionValue tsOption;
	tsOption.type = pcpp::IPv4TimestampOptionValue::TimestampOnly;
	tsOption.timestamps.push_back(82524601);
	for (int i = 0; i < 8; i++)
	{
		tsOption.timestamps.push_back(0);
	}
	PTF_ASSERT_FALSE(ipLayer->addOption(pcpp::IPv4OptionBuilder(tsOption)).isNull());
	ipOpt2.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipOpt2.getRawPacket()->getRawDataLen(), bufferLength22);
	PTF_ASSERT_BUF_COMPARE(ipOpt2.getRawPacket()->getRawData(), buffer22, ipOpt2.getRawPacket()->getRawDataLen());

	ipLayer = ipOpt3.getLayerOfType<pcpp::IPv4Layer>();
	uint16_t routerAlerVal = 0;
	PTF_ASSERT_FALSE(
	    ipLayer->addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_RouterAlert, (uint16_t)routerAlerVal)).isNull());
	ipOpt3.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipOpt3.getRawPacket()->getRawDataLen(), bufferLength33);
	PTF_ASSERT_BUF_COMPARE(ipOpt3.getRawPacket()->getRawData(), buffer33, ipOpt3.getRawPacket()->getRawDataLen());

	ipLayer = ipOpt4.getLayerOfType<pcpp::IPv4Layer>();
	std::vector<pcpp::IPv4Address> ipListValue;
	ipListValue.push_back(pcpp::IPv4Address("1.2.3.4"));
	ipListValue.push_back(pcpp::IPv4Address("10.0.0.138"));
	ipListValue.push_back(pcpp::IPv4Address("10.0.0.138"));
	for (int i = 0; i < 6; i++)
		ipListValue.push_back(pcpp::IPv4Address::Zero);
	PTF_ASSERT_FALSE(ipLayer->addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_RecordRoute, ipListValue)).isNull());
	PTF_ASSERT_FALSE(ipLayer->addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_EndOfOptionsList, nullptr, 0)).isNull());
	ipOpt4.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipOpt4.getRawPacket()->getRawDataLen(), bufferLength44);
	PTF_ASSERT_BUF_COMPARE(ipOpt4.getRawPacket()->getRawData(), buffer44, ipOpt4.getRawPacket()->getRawDataLen());

	ipLayer = ipOpt5.getLayerOfType<pcpp::IPv4Layer>();
	tsOption.clear();
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_TRUE(ipLayer->addOption(pcpp::IPv4OptionBuilder(tsOption)).isNull());
	pcpp::Logger::getInstance().enableLogs();
	tsOption.type = pcpp::IPv4TimestampOptionValue::TimestampAndIP;
	tsOption.ipAddresses.push_back(pcpp::IPv4Address("10.0.0.6"));
	tsOption.ipAddresses.push_back(pcpp::IPv4Address("10.0.0.138"));
	tsOption.ipAddresses.push_back(pcpp::IPv4Address("10.0.0.138"));
	tsOption.ipAddresses.push_back(pcpp::IPv4Address::Zero);
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_TRUE(ipLayer->addOption(pcpp::IPv4OptionBuilder(tsOption)).isNull());
	pcpp::Logger::getInstance().enableLogs();
	tsOption.timestamps.push_back(70037668);
	tsOption.timestamps.push_back(77233718);
	tsOption.timestamps.push_back(77233718);
	tsOption.timestamps.push_back(0);
	pcpp::IPv4Option optData = ipLayer->addOption(pcpp::IPv4OptionBuilder(tsOption));
	PTF_ASSERT_FALSE(optData.isNull());
	PTF_ASSERT_EQUAL(optData.getIPv4OptionType(), pcpp::IPV4OPT_Timestamp, enum);
	PTF_ASSERT_EQUAL(optData.getTotalSize(), 36);
	tsOption.clear();
	tsOption = optData.getTimestampOptionValue();
	PTF_ASSERT_EQUAL(tsOption.type, pcpp::IPv4TimestampOptionValue::TimestampAndIP, enum);
	PTF_ASSERT_EQUAL(tsOption.timestamps.size(), 3);
	PTF_ASSERT_EQUAL(tsOption.timestamps.at(1), htobe32(77233718));
	PTF_ASSERT_EQUAL(tsOption.ipAddresses.size(), 3);
	PTF_ASSERT_EQUAL(tsOption.ipAddresses.at(2), pcpp::IPv4Address("10.0.0.138"));
	ipOpt5.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipOpt5.getRawPacket()->getRawDataLen(), bufferLength55);
	PTF_ASSERT_BUF_COMPARE(ipOpt5.getRawPacket()->getRawData(), buffer55, ipOpt5.getRawPacket()->getRawDataLen());

	ipLayer = ipOpt6.getLayerOfType<pcpp::IPv4Layer>();
	ipListValue.clear();
	ipListValue.push_back(pcpp::IPv4Address::Zero);
	optData = ipLayer->addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_StrictSourceRoute, ipListValue));
	PTF_ASSERT_FALSE(optData.isNull());
	PTF_ASSERT_EQUAL(optData.getIPv4OptionType(), pcpp::IPV4OPT_StrictSourceRoute, enum);
	PTF_ASSERT_EQUAL(optData.getTotalSize(), 7);
	ipListValue = optData.getValueAsIpList();
	PTF_ASSERT_EQUAL(ipListValue.size(), 0);
	optData = ipLayer->addOptionAfter(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_NOP, nullptr, 0));
	PTF_ASSERT_FALSE(optData.isNull());
	PTF_ASSERT_EQUAL(optData.getIPv4OptionType(), pcpp::IPV4OPT_NOP, enum);
	PTF_ASSERT_EQUAL(optData.getTotalSize(), 1);
	ipOpt6.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipOpt6.getRawPacket()->getRawDataLen(), bufferLength66);
	PTF_ASSERT_BUF_COMPARE(ipOpt6.getRawPacket()->getRawData(), buffer66, ipOpt6.getRawPacket()->getRawDataLen());

	ipLayer = ipOpt7.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_FALSE(ipLayer->addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_NOP, nullptr, 0)).isNull());
	ipListValue.clear();
	ipListValue.push_back(pcpp::IPv4Address::Zero);
	PTF_ASSERT_FALSE(ipLayer->addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_LooseSourceRoute, ipListValue)).isNull());
	ipOpt7.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipOpt7.getRawPacket()->getRawDataLen(), bufferLength77);
	PTF_ASSERT_BUF_COMPARE(ipOpt7.getRawPacket()->getRawData(), buffer77, ipOpt7.getRawPacket()->getRawDataLen());
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 2);

	tsOption.clear();
	tsOption.type = pcpp::IPv4TimestampOptionValue::TimestampAndIP;
	tsOption.ipAddresses.push_back(pcpp::IPv4Address("10.0.0.6"));
	tsOption.ipAddresses.push_back(pcpp::IPv4Address::Zero);
	tsOption.timestamps.push_back(70037668);
	tsOption.timestamps.push_back(70037669);
	PTF_ASSERT_FALSE(ipLayer->addOptionAfter(pcpp::IPv4OptionBuilder(tsOption), pcpp::IPV4OPT_NOP).isNull());
	PTF_ASSERT_FALSE(
	    ipLayer->addOptionAfter(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_RouterAlert, (uint16_t)routerAlerVal)).isNull());
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 4);
	ipOpt7.computeCalculateFields();
	tsOption.clear();
	tsOption.type = pcpp::IPv4TimestampOptionValue::TimestampOnly;
	tsOption.timestamps.push_back(70037670);
	PTF_ASSERT_FALSE(ipLayer->addOption(pcpp::IPv4OptionBuilder(tsOption)).isNull());
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 5);
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_TRUE(
	    ipLayer->addOption(pcpp::IPv4OptionBuilder(pcpp::IPV4OPT_RouterAlert, (uint16_t)routerAlerVal)).isNull());
	pcpp::Logger::getInstance().enableLogs();
	ipOpt7.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 5);

	PTF_ASSERT_TRUE(ipLayer->removeOption(pcpp::IPV4OPT_Timestamp));
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 4);
	ipOpt7.computeCalculateFields();
	PTF_ASSERT_TRUE(ipLayer->removeOption(pcpp::IPV4OPT_RouterAlert));
	ipOpt7.computeCalculateFields();
	PTF_ASSERT_TRUE(ipLayer->removeOption(pcpp::IPV4OPT_Timestamp));
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 2);
	ipOpt7.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipOpt7.getRawPacket()->getRawDataLen(), bufferLength77);
	PTF_ASSERT_BUF_COMPARE(ipOpt7.getRawPacket()->getRawData(), buffer77, ipOpt7.getRawPacket()->getRawDataLen());

	PTF_ASSERT_TRUE(ipLayer->removeAllOptions());
	ipOpt7.computeCalculateFields();
	PTF_ASSERT_EQUAL(ipOpt7.getRawPacketReadOnly()->getRawDataLen(), 42);
	ipLayer = ipOpt7.getLayerOfType<pcpp::IPv4Layer>();
	PTF_ASSERT_EQUAL(ipLayer->getOptionCount(), 0);

	delete[] buffer11;
	delete[] buffer22;
	delete[] buffer33;
	delete[] buffer44;
	delete[] buffer55;
	delete[] buffer66;
	delete[] buffer77;
}  // Ipv4OptionsEditTest

PTF_TEST_CASE(IPv4UdpChecksum)
{
	for (int i = 1; i < 6; i++)
	{
		std::stringstream strStream;
		strStream << "PacketExamples/UdpPacket4Checksum" << i << ".dat";
		std::string fileName = strStream.str();

		timeval time;
		gettimeofday(&time, nullptr);

		READ_FILE_AND_CREATE_PACKET(1, fileName.c_str());

		pcpp::Packet udpPacket(&rawPacket1);
		pcpp::UdpLayer* udpLayer = udpPacket.getLayerOfType<pcpp::UdpLayer>();
		PTF_ASSERT_NOT_NULL(udpLayer);
		uint16_t packetChecksum = udpLayer->getUdpHeader()->headerChecksum;
		udpLayer->computeCalculateFields();
		PTF_ASSERT_EQUAL(udpLayer->getUdpHeader()->headerChecksum, packetChecksum, hex);
	}
}  // Ipv4UdpChecksum
