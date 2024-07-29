#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Logger.h"
#include "Packet.h"
#include "DhcpV6Layer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(DhcpV6ParsingTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/dhcpv6_1.dat");

	pcpp::Packet dhcpv6Packet(&rawPacket1);
	pcpp::DhcpV6Layer* dhcpv6Layer = dhcpv6Packet.getLayerOfType<pcpp::DhcpV6Layer>();
	PTF_ASSERT_NOT_NULL(dhcpv6Layer);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getMessageType(), pcpp::DHCPV6_SOLICIT);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getMessageTypeAsString(), "Solicit");
	PTF_ASSERT_EQUAL(dhcpv6Layer->getTransactionID(), 0x9a0006);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getOptionCount(), 6);
	PTF_ASSERT_EQUAL(dhcpv6Layer->toString(), "DHCPv6 Layer, Solicit message");

	pcpp::DhcpV6OptionType optTypeArr[] = { pcpp::DHCPV6_OPT_CLIENTID,     pcpp::DHCPV6_OPT_ORO,
		                                    pcpp::DHCPV6_OPT_ELAPSED_TIME, pcpp::DHCPV6_OPT_USER_CLASS,
		                                    pcpp::DHCPV6_OPT_VENDOR_CLASS, pcpp::DHCPV6_OPT_IA_NA };
	size_t optDataSizeArr[] = { 18, 14, 2, 10, 51, 12 };
	std::string optDataAsHexString[] = {
		"000200000009464745313934373134515300",
		"0017001800f300f2003b00f20027",
		"0000",
		"6578722d636f6e666967",
		"00000009002d505845436c69656e743a417263683a30303030393a554e44493a3030333031303a5049443a4e43532d35353038",
		"1d00fcea00000e1000001518"
	};

	pcpp::DhcpV6Option dhcpOption = dhcpv6Layer->getFirstOptionData();
	for (size_t i = 0; i < dhcpv6Layer->getOptionCount(); i++)
	{
		PTF_ASSERT_TRUE(dhcpOption.isNotNull());
		PTF_ASSERT_EQUAL(dhcpOption.getType(), optTypeArr[i]);
		PTF_ASSERT_EQUAL(dhcpOption.getDataSize(), optDataSizeArr[i]);
		PTF_ASSERT_EQUAL(dhcpOption.getTotalSize(), optDataSizeArr[i] + 4);
		PTF_ASSERT_EQUAL(dhcpOption.getValueAsHexString(), optDataAsHexString[i]);
		dhcpOption = dhcpv6Layer->getNextOptionData(dhcpOption);
	}
}  // DhcpV6ParsingTest

PTF_TEST_CASE(DhcpV6CreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/dhcpv6_2.dat");

	uint8_t origBuffer[1500];

	pcpp::DhcpV6Layer newDhcpV6Layer(pcpp::DHCPV6_ADVERTISE, 0x9a0006);
	PTF_ASSERT_EQUAL(newDhcpV6Layer.getTransactionID(), 0x9a0006);

	memcpy(origBuffer, buffer1, bufferLength1);
	pcpp::Packet dhcpv6Packet(&rawPacket1);
	pcpp::DhcpV6Layer* origDhcpV6Layer = dynamic_cast<pcpp::DhcpV6Layer*>(dhcpv6Packet.detachLayer(pcpp::DHCPv6));
	PTF_ASSERT_NOT_NULL(origDhcpV6Layer);

	// 1st option
	pcpp::DhcpV6Option option = newDhcpV6Layer.addOption(pcpp::DhcpV6OptionBuilder(
	    pcpp::DHCPV6_OPT_IA_NA, "1d00fcea00000000000000000005001820010dba0100000000000000000000300000017700000258"));
	PTF_ASSERT_EQUAL(option.getType(), pcpp::DHCPV6_OPT_IA_NA);
	PTF_ASSERT_EQUAL(option.getDataSize(), 40);
	PTF_ASSERT_EQUAL(newDhcpV6Layer.getOptionCount(), 1);
	// 4th option
	option = newDhcpV6Layer.addOption(
	    pcpp::DhcpV6OptionBuilder(pcpp::DHCPV6_OPT_DNS_SERVERS, "20010dba010000000000000000000001"));
	PTF_ASSERT_EQUAL(option.getType(), pcpp::DHCPV6_OPT_DNS_SERVERS);
	PTF_ASSERT_EQUAL(option.getDataSize(), 16);
	PTF_ASSERT_EQUAL(newDhcpV6Layer.getOptionCount(), 2);
	// 3rd option
	option = newDhcpV6Layer.addOptionBefore(
	    pcpp::DhcpV6OptionBuilder(pcpp::DHCPV6_OPT_SERVERID, "000100012154eee7000c29703dd8"),
	    pcpp::DHCPV6_OPT_DNS_SERVERS);
	PTF_ASSERT_EQUAL(option.getType(), pcpp::DHCPV6_OPT_SERVERID);
	PTF_ASSERT_EQUAL(option.getDataSize(), 14);
	PTF_ASSERT_EQUAL(newDhcpV6Layer.getOptionCount(), 3);
	// 2nd option
	option = newDhcpV6Layer.addOptionAfter(
	    pcpp::DhcpV6OptionBuilder(pcpp::DHCPV6_OPT_CLIENTID, "000200000009464745313934373134515300"),
	    pcpp::DHCPV6_OPT_IA_NA);
	PTF_ASSERT_EQUAL(option.getType(), pcpp::DHCPV6_OPT_CLIENTID);
	PTF_ASSERT_EQUAL(option.getDataSize(), 18);
	PTF_ASSERT_EQUAL(newDhcpV6Layer.getOptionCount(), 4);
	// 6th option
	option = newDhcpV6Layer.addOption(pcpp::DhcpV6OptionBuilder(
	    pcpp::DHCPV6_OPT_BOOTFILE_URL,
	    "687474703a2f2f5b323030313a6462613a3130303a3a315d3a393039302f657868617573746976655f7a74705f7363726970742e7079"));
	PTF_ASSERT_EQUAL(option.getType(), pcpp::DHCPV6_OPT_BOOTFILE_URL);
	PTF_ASSERT_EQUAL(option.getDataSize(), 54);
	PTF_ASSERT_EQUAL(newDhcpV6Layer.getOptionCount(), 5);
	// 5th option
	option = newDhcpV6Layer.addOptionAfter(
	    pcpp::DhcpV6OptionBuilder(pcpp::DHCPV6_OPT_DOMAIN_LIST, "05636973636f056c6f63616c00"),
	    pcpp::DHCPV6_OPT_DNS_SERVERS);
	PTF_ASSERT_EQUAL(option.getType(), pcpp::DHCPV6_OPT_DOMAIN_LIST);
	PTF_ASSERT_EQUAL(option.getDataSize(), 13);
	PTF_ASSERT_EQUAL(newDhcpV6Layer.getOptionCount(), 6);

	pcpp::Logger::getInstance().suppressLogs();
	// prev/next option doesn't exist in layer
	option = newDhcpV6Layer.addOptionAfter(pcpp::DhcpV6OptionBuilder(pcpp::DHCPV6_OPT_DOMAIN_LIST, "05"),
	                                       pcpp::DHCPV6_OPT_ELAPSED_TIME);
	PTF_ASSERT_TRUE(option.isNull());
	option = newDhcpV6Layer.addOptionBefore(pcpp::DhcpV6OptionBuilder(pcpp::DHCPV6_OPT_DOMAIN_LIST, "05"),
	                                        pcpp::DHCPV6_OPT_ELAPSED_TIME);
	PTF_ASSERT_TRUE(option.isNull());

	// string is not a valid hex stream
	option = newDhcpV6Layer.addOption(pcpp::DhcpV6OptionBuilder(pcpp::DHCPV6_OPT_DOMAIN_LIST, "xyza"));
	PTF_ASSERT_TRUE(option.isNull());

	PTF_ASSERT_EQUAL(newDhcpV6Layer.getOptionCount(), 6);
	pcpp::Logger::getInstance().enableLogs();

	PTF_ASSERT_EQUAL(newDhcpV6Layer.getDataLen(), origDhcpV6Layer->getDataLen());
	PTF_ASSERT_BUF_COMPARE(newDhcpV6Layer.getData(), origDhcpV6Layer->getData(), origDhcpV6Layer->getDataLen());

	PTF_ASSERT_TRUE(dhcpv6Packet.addLayer(&newDhcpV6Layer));
	dhcpv6Packet.computeCalculateFields();
	PTF_ASSERT_EQUAL(dhcpv6Packet.getRawPacket()->getRawDataLen(), bufferLength1);
	PTF_ASSERT_BUF_COMPARE(dhcpv6Packet.getRawPacket()->getRawData(), origBuffer, bufferLength1);
	delete origDhcpV6Layer;
}  // DhcpV6CreationTest

PTF_TEST_CASE(DhcpV6EditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/dhcpv6_1.dat");

	pcpp::Packet dhcpv6Packet(&rawPacket1);
	pcpp::DhcpV6Layer* dhcpv6Layer = dhcpv6Packet.getLayerOfType<pcpp::DhcpV6Layer>();
	PTF_ASSERT_NOT_NULL(dhcpv6Layer);
	dhcpv6Layer->setMessageType(pcpp::DHCPV6_RELEASE);
	dhcpv6Layer->setTransactionID(0x12345);
	PTF_ASSERT_TRUE(dhcpv6Layer->removeOption(pcpp::DHCPV6_OPT_ELAPSED_TIME));
	PTF_ASSERT_EQUAL(dhcpv6Layer->getOptionCount(), 5);
	PTF_ASSERT_TRUE(dhcpv6Layer->removeOption(pcpp::DHCPV6_OPT_VENDOR_CLASS));
	PTF_ASSERT_EQUAL(dhcpv6Layer->getOptionCount(), 4);
	// try removing option that doesn't exist
	PTF_ASSERT_FALSE(dhcpv6Layer->removeOption(pcpp::DHCPV6_OPT_NISP_SERVERS));
	dhcpv6Layer->addOption(pcpp::DhcpV6OptionBuilder(pcpp::DHCPV6_OPT_DOMAIN_LIST, "05636973636f056c6f63616c00"));
	PTF_ASSERT_EQUAL(dhcpv6Layer->getOptionCount(), 5);

	// reload layer
	dhcpv6Layer = dhcpv6Packet.getLayerOfType<pcpp::DhcpV6Layer>();
	PTF_ASSERT_NOT_NULL(dhcpv6Layer);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getMessageType(), pcpp::DHCPV6_RELEASE);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getTransactionID(), 0x12345);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getOptionCount(), 5);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getDataLen(), 91);

	dhcpv6Layer->removeAllOptions();
	PTF_ASSERT_EQUAL(dhcpv6Layer->getOptionCount(), 0);
	PTF_ASSERT_EQUAL(dhcpv6Layer->getDataLen(), 4);
}  // DhcpV6EditTest
